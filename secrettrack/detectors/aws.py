import re
from typing import List, Dict, Any
from .base import BaseDetector


class AWSDetector(BaseDetector):
    """Detector for AWS secrets."""
    
    def _get_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "aws_access_key_id",
                "pattern": re.compile(r'(?i)(?:aws_access_key_id|aws_key|access_key_id)[\s:=]+[\'"](A[SK]IA[0-9A-Z]{16})[\'"]'),
            },
            {
                "name": "aws_secret_access_key",
                "pattern": re.compile(r'(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)[\s:=]+[\'"]([0-9a-zA-Z/+]{40})[\'"]'),
            },
            {
                "name": "aws_session_token",
                "pattern": re.compile(r'(?i)(?:aws_session_token|session_token)[\s:=]+[\'"]([0-9a-zA-Z/+]{340,})[\'"]'),
            },
        ]
    
    def get_secret_type(self) -> str:
        return "aws"
    
    def _get_risk_description(self) -> str:
        return "Full AWS account compromise, resource creation/deletion, data exfiltration, unauthorized billing"
    
    def _get_recommendation(self) -> str:
        return """1. Rotate the compromised key immediately via AWS Console
2. Remove the key from git history using BFG or git filter-branch
3. Check CloudTrail logs for unauthorized activity
4. Use AWS Secrets Manager or Parameter Store for credential management
5. Implement IAM roles instead of long-term access keys"""