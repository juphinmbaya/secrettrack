import re
from typing import List, Dict, Any
from .base import BaseDetector


class GitHubDetector(BaseDetector):
    """Detector for GitHub tokens and keys."""
    
    def _get_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "github_personal_access_token",
                "pattern": re.compile(r'(?i)(?:github_token|gh_token|personal_access_token)[\s:=]+[\'"](gh[pousr]_[A-Za-z0-9_]{36,255})[\'"]'),
            },
            {
                "name": "github_oauth_token",
                "pattern": re.compile(r'(?i)(?:github_oauth|gh_oauth)[\s:=]+[\'"]([0-9a-f]{40})[\'"]'),
            },
            {
                "name": "github_app_private_key",
                "pattern": re.compile(r'-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END RSA PRIVATE KEY-----'),
            },
            {
                "name": "github_ssh_private_key",
                "pattern": re.compile(r'-----BEGIN (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----'),
            },
        ]
    
    def get_secret_type(self) -> str:
        return "github"
    
    def _get_risk_description(self) -> str:
        return "Repository takeover, code modification, secrets access, organization compromise"
    
    def _get_recommendation(self) -> str:
        return """1. Revoke the token immediately in GitHub Settings → Developer settings → Personal access tokens
2. Rotate any dependent credentials
3. Remove from git history using BFG or git filter-branch
4. Enable required reviews for sensitive operations
5. Use GitHub Actions secrets or environment variables"""