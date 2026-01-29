import re
from typing import List, Dict, Any
from .base import BaseDetector


class StripeDetector(BaseDetector):
    """Detector for Stripe API keys."""
    
    def _get_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "stripe_live_secret_key",
                "pattern": re.compile(r'(?i)(?:stripe_secret_key|stripe_api_key)[\s:=]+[\'"](sk_live_[0-9a-zA-Z]{24,})[\'"]'),
            },
            {
                "name": "stripe_test_secret_key",
                "pattern": re.compile(r'(?i)(?:stripe_test_key|stripe_test_secret)[\s:=]+[\'"](sk_test_[0-9a-zA-Z]{24,})[\'"]'),
            },
            {
                "name": "stripe_live_publishable_key",
                "pattern": re.compile(r'(?i)(?:stripe_publishable_key)[\s:=]+[\'"](pk_live_[0-9a-zA-Z]{24,})[\'"]'),
            },
            {
                "name": "stripe_webhook_secret",
                "pattern": re.compile(r'(?i)(?:stripe_webhook_secret|whsec_)[\s:=]+[\'"](whsec_[0-9a-zA-Z]{24,})[\'"]'),
            },
        ]
    
    def get_secret_type(self) -> str:
        return "stripe"
    
    def _get_risk_description(self) -> str:
        return "Full payment system takeover, customer data access, unauthorized charges, refund issuance"
    
    def _get_recommendation(self) -> str:
        return """1. Rotate the key immediately in Stripe Dashboard → Developers → API keys
2. Revoke compromised key
3. Check for unauthorized charges and refunds
4. Remove from git history using BFG or git filter-branch
5. Use Stripe CLI for local development with test keys only
6. Implement webhook signature verification"""