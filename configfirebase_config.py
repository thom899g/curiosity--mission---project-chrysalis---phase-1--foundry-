"""
Firebase configuration and initialization with proper error handling.
Critical: Never hardcode credentials - use environment variables.
"""
import os
from typing import Optional, Dict, Any
import structlog
from firebase_admin import credentials, firestore, initialize_app
from firebase_admin.exceptions import FirebaseError

logger = structlog.get_logger(__name__)

class FirebaseConfig:
    """Secure Firebase configuration management"""
    
    # Collection names matching architectural specification
    COLLECTIONS = {
        'events': 'events',
        'opportunities': 'opportunities', 
        'trades': 'trades',
        'ledger': 'ledger',
        'treasury': 'treasury',
        'circuit_breakers': 'circuit_breakers'
    }
    
    def __init__(self):
        self._app = None
        self._db = None
        self._initialized = False
        
    def initialize(self, credential_path: Optional[str] = None) -> bool:
        """
        Initialize Firebase connection with fallback strategies
        
        Args:
            credential_path: Optional path to service account JSON
            
        Returns:
            bool: True if initialization successful
            
        Raises:
            FirebaseError: If Firebase initialization fails after all attempts
        """
        try:
            # Priority 1: Environment variable for credential JSON
            if os.getenv('FIREBASE_CREDENTIALS_JSON'):
                import json
                cred_dict = json.loads(os.getenv('FIREBASE_CREDENTIALS_JSON'))
                cred = credentials.Certificate(cred_dict)
                logger.info("firebase_credentials_source", source="environment_variable")
                
            # Priority 2: File path from environment
            elif credential_path or os.getenv('GOOGLE_APPLICATION_CREDENTIALS'):
                path = credential_path or os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
                if os.path.exists(path):
                    cred = credentials.Certificate(path)
                    logger.info("firebase_credentials_source", source="file_path", path=path)
                else:
                    raise FileNotFoundError(f"Firebase credential file not found: {path}")
                    
            # Priority 3: Default application credentials (for GCP environments)
            else:
                cred = credentials.ApplicationDefault()
                logger.info("firebase_credentials_source", source="application_default")
                
            # Initialize Firebase
            self._app = initialize_app(cred)
            self._db = firestore.client(self._app)
            
            # Verify connection
            self._db.collection('health_check').document('ping').set({
                'timestamp': firestore.SERVER_TIMESTAMP,
                'status': 'active'
            }, merge=True)
            
            self._initialized = True
            logger.info("firebase_initialized_successfully")
            return True
            
        except Exception as e:
            logger.error("firebase_initialization_failed", 
                        error=str(e),
                        error_type=type(e).__name__)
            self._initialized = False
            raise FirebaseError(f"Firebase initialization failed: {str(e)}") from e
    
    @property
    def db(self) -> firestore.Client:
        """Get Firestore client with validation"""
        if not self._initialized or not self._db:
            raise RuntimeError("Firebase not initialized. Call initialize() first.")
        return self._db
    
    @property
    def is_initialized(self) -> bool:
        return self._initialized
    
    def get_collection(self, collection_name: str) -> firestore.CollectionReference:
        """Get collection reference with validation"""
        if collection_name not in self.COLLECTIONS:
            raise ValueError(f"Invalid collection: {collection_name}")
        return self.db.collection(self.COLLECTIONS[collection_name])
    
# Global instance
firebase_config = FirebaseConfig()