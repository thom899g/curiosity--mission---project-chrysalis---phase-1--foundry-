"""
Event Bus implementation using Firestore as primary event store.
Implements cryptographic signatures for verifiable autonomy.
"""
import hashlib
import json
import time
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import structlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from config.firebase_config import firebase_config

logger = structlog.get_logger(__name__)

@dataclass
class Event:
    """Immutable event with cryptographic signature"""
    event_id: str
    event_type: str
    payload: Dict[str, Any]
    timestamp: datetime
    previous_event_hash: Optional[str] = None
    signature: Optional[str] = None
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Firestore storage"""
        data = asdict(self)
        data['timestamp'] = data['timestamp'].isoformat() if isinstance(data['timestamp'], datetime) else data['timestamp']
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """Create Event from dictionary"""
        if isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)

class CryptographicSigner:
    """ECDSA signer for event signatures"""
    
    def __init__(self, private_key_pem: Optional[str] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        else:
            # Generate new key for this instance
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
    def sign_event(self, event_data: Dict[str, Any]) -> str:
        """Sign event data and return base64 signature"""
        # Create deterministic JSON string
        event_str = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
        
        # Sign using ECDSA
        signature = self.private_key.sign(
            event_str.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Return hex signature
        return signature.hex()
    
    def verify_signature(self, event_data: Dict[str, Any], signature: str) -> bool:
        """Verify event signature"""
        try:
            event_str = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
            self.private_key.public_key().verify(
                bytes.fromhex(signature),
                event_str.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

class EventBus:
    """Firestore-based event bus with cryptographic integrity"""
    
    def __init__(self):
        self.db = firebase_config.db
        self.signer = CryptographicSigner()
        self._listeners: Dict[str, List[Callable]] = {}
        self._last_event_hash: Optional[str] = None
        
    def _calculate_event_hash(self, event: Event) -> str:
        """Calculate SHA-256 hash of event for chain integrity"""
        event_str = json.dumps(event.to_dict(), sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()
    
    def publish(self, event_type: str, payload: Dict[str, Any]) -> str:
        """
        Publish event with cryptographic signature
        
        Args:
            event_type: Type of event (scanner.found, trade.executed, etc.)
            payload: Event data
            
        Returns:
            str: Event ID
            
        Raises:
            RuntimeError: If Firebase not initialized
        """
        if not firebase_config.is_initialized:
            raise RuntimeError("Firebase not initialized")
        
        try:
            # Create event
            event_id = f"{event_type}_{int(time.time() * 1000)}"
            timestamp = datetime.now(timezone.utc)
            
            event = Event(
                event_id=event_id,
                event_type=event_type,
                payload=payload,
                timestamp=timestamp,
                previous_event_hash=self._last_event_hash
            )
            
            # Sign event
            event_data = event.to_dict()
            signature = self.signer.sign_event(event_data)
            event.signature = signature
            
            # Calculate hash for next event
            self._last_event_hash = self._calculate_event_hash(event)
            
            # Store in Firestore
            event_ref = firebase_config.get_collection('events').document(event_id)
            event_ref.set(event.to_dict())
            
            logger.info("event_published", 
                       event_id=event_id,
                       event_type=event_type,
                       previous_hash=self._last_event_hash)
            
            # Notify local listeners
            self._notify_listeners(event_type, event)
            
            return event_id
            
        except Exception as e:
            logger.error("event_publish_failed",
                        event_type=event_type,
                        error=str(e))
            raise
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to event type with callback"""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)
        
        # Also set up Firestore listener for persistence
        self._setup_firestore_listener(event_type)
    
    def _setup_firestore_listener(self, event_type: str):
        """Set up Firestore real-time listener for event type"""
        def on_snapshot(col_snapshot, changes, read_time):
            for change in changes:
                if change.type.name == 'ADDED':
                    event_data = change.document.to_dict()
                    event = Event.from_dict(event_data)
                    self._notify_listeners(event_type, event)
        
        # Create query for this event type
        events_ref = firebase_config.get_collection('events')
        query = events_ref.where('event_type', '==', event_type).order_by('timestamp')
        
        # Start listening (this runs in background)
        query.on_snapshot(on_snapshot)
    
    def _notify_listeners(self, event_type: str, event: Event):
        """Notify all listeners for event type"""
        if event_type in self._listeners:
            for callback in self._listeners[event_type]:
                try:
                    callback(event)
                except Exception as e:
                    logger.error("event_listener_error",
                                event_id=event.event_id,
                                error=str(e))
    
    def get_event_chain(self, limit: int = 100) -> List[Event]:
        """Retrieve event chain for verification"""
        events_ref = firebase_config.get_collection('events')
        query = events_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
        
        events = []
        for doc in query.stream():
            events.append(Event.from_dict(doc.to_dict()))
        
        return list(reversed(events))  # Return in chronological order
    
    def verify_event_chain(self) -> bool:
        """Verify cryptographic integrity of event chain"""
        events = self.get_event_chain(1000)
        
        if not events:
            return True
        
        previous_hash = None
        for event in events:
            # Verify signature
            if event.signature:
                event_data = event.to_dict()
                event_data.pop('signature', None)
                if not self.signer.verify_signature(event_data, event.signature):
                    logger.error("event_signature_invalid", event_id=event.event_id)
                    return False
            
            # Verify hash chain
            current_hash = self._calculate_event_hash(event)
            if event.previous_event_hash != previous_hash:
                logger.error("event_hash_chain_broken", 
                           event_id=event.event_id,
                           expected=previous_hash,
                           actual=event.previous_event_hash)
                return False
            
            previous_hash = current_hash
        
        return True