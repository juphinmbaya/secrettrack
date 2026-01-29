import re
import json
from typing import List, Dict, Any
from .base import BaseDetector


class FirebaseDetector(BaseDetector):
    """Detector for Firebase credentials."""
    
    def _get_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "firebase_api_key",
                "pattern": re.compile(r'(?i)(?:firebase_api_key|apiKey)[\s:=]+[\'"](AIza[0-9A-Za-z\-_]{35})[\'"]'),
            },
            {
                "name": "firebase_config",
                "pattern": re.compile(r'(?i)firebaseConfig\s*=\s*\{[^}]+apiKey[^}]+projectId[^}]+\}'),
            },
            {
                "name": "firebase_service_account",
                "pattern": re.compile(r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----'),
            },
        ]
    
    def get_secret_type(self) -> str:
        return "firebase"
    
    def _get_risk_description(self) -> str:
        return "Database access, user authentication bypass, storage manipulation, cloud function invocation"
    
    def _get_recommendation(self) -> str:
        return """1. Rotate API keys in Firebase Console → Project settings → General
2. Restrict API key usage to specific domains/IPs
3. Review and tighten Firebase Security Rules
4. Remove service account keys and use Application Default Credentials
5. Enable Firebase App Check for additional protection"""