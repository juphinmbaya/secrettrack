import re
from pathlib import Path
from typing import Optional


class ConfidenceAnalyzer:
    """Calculates confidence score for potential secrets."""
    
    # High confidence indicators
    HIGH_CONFIDENCE_PATTERNS = [
        r'sk_live_',
        r'AKIA[0-9A-Z]{16}',
        r'gh[pousr]_[A-Za-z0-9_]{36}',
        r'-----BEGIN PRIVATE KEY-----',
    ]
    
    # Low confidence indicators (likely false positives)
    LOW_CONFIDENCE_INDICATORS = [
        r'example',
        r'test',
        r'dummy',
        r'sample',
        r'placeholder',
        r'changeme',
        r'your_',
        r'xxxx',
        r'0000',
    ]
    
    def calculate_confidence(self, secret: str, line: str, 
                            filepath: Optional[Path]) -> float:
        """Calculate confidence score (0.0 to 1.0)."""
        confidence = 0.5  # Base confidence
        
        # Check for high confidence patterns
        if any(re.search(pattern, secret, re.IGNORECASE) 
              for pattern in self.HIGH_CONFIDENCE_PATTERNS):
            confidence += 0.3
        
        # Check for low confidence indicators
        full_context = line.lower()
        if any(indicator in full_context for indicator in self.LOW_CONFIDENCE_INDICATORS):
            confidence -= 0.4
        
        # Check file type
        if filepath:
            if filepath.suffix in {'.md', '.txt', '.rst'}:  # Documentation
                confidence -= 0.2
            elif 'test' in filepath.stem.lower():
                confidence -= 0.2
        
        # Check if it looks like a real secret
        if self._looks_like_real_secret(secret):
            confidence += 0.2
        
        # Normalize to 0.0-1.0 range
        return max(0.0, min(1.0, confidence))
    
    def _looks_like_real_secret(self, secret: str) -> bool:
        """Check if the secret looks like a real credential."""
        # Too short
        if len(secret) < 8:
            return False
        
        # Contains spaces
        if ' ' in secret:
            return False
        
        # All same character
        if len(set(secret)) < 3:
            return False
        
        # Common placeholder patterns
        placeholders = ['password', 'secret', 'key', 'token']
        if any(placeholder in secret.lower() for placeholder in placeholders):
            return False
        
        return True