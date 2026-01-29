import re
from typing import List, Dict, Any
from .base import BaseDetector


class GenericDetector(BaseDetector):
    """Detector for generic secrets and credentials."""
    
    def _get_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "password_in_code",
                "pattern": re.compile(r'(?i)(?:password|passwd|pwd|secret)[\s:=]+[\'"]([^\'"]{6,128})[\'"]'),
            },
            {
                "name": "jwt_token",
                "pattern": re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
            },
            {
                "name": "api_key_generic",
                "pattern": re.compile(r'(?i)(?:api[_-]?key|apikey)[\s:=]+[\'"]([0-9a-zA-Z\-_]{20,100})[\'"]'),
            },
            {
                "name": "bearer_token",
                "pattern": re.compile(r'(?i)bearer[\s]+([0-9a-zA-Z\-_=]{20,})'),
            },
            {
                "name": "private_key",
                "pattern": re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[A-Za-z0-9+/=\s\n]+-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            },
            {
                "name": "connection_string",
                "pattern": re.compile(r'(?i)(?:postgresql|mysql|mongodb|redis)://[^\s"\']+'),
            },
            {
                "name": "slack_token",
                "pattern": re.compile(r'(xox[abpors]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24})'),
            },
        ]
    
    def get_secret_type(self) -> str:
        return "generic"
    
    def _get_risk_description(self) -> str:
        return "Varies based on the service: authentication bypass, data access, service impersonation"
    
    def _get_recommendation(self) -> str:
        return """1. Identify the service this credential belongs to
2. Rotate/revoke the credential immediately
3. Check for unauthorized access
4. Remove from git history
5. Use environment variables or secret management solution"""