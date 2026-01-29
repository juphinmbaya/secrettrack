import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
import hashlib

from secretsfinder.analyzer.context import ContextAnalyzer
from secretsfinder.analyzer.confidence import ConfidenceAnalyzer


class BaseDetector(ABC):
    """Base class for all secret detectors."""
    
    def __init__(self):
        self.context_analyzer = ContextAnalyzer()
        self.confidence_analyzer = ConfidenceAnalyzer()
        self.patterns = self._get_patterns()
    
    @abstractmethod
    def _get_patterns(self) -> List[Dict[str, Any]]:
        """Return list of patterns to search for."""
        pass
    
    @abstractmethod
    def get_secret_type(self) -> str:
        """Return the type of secret this detector finds."""
        pass
    
    def scan_line(self, line: str, line_num: int, filepath: Optional[Path], 
                  commit_hash: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan a line of text for secrets."""
        results = []
        
        for pattern_info in self.patterns:
            pattern = pattern_info["pattern"]
            matches = pattern.finditer(line)
            
            for match in matches:
                # Calculate confidence
                confidence = self.confidence_analyzer.calculate_confidence(
                    match.group(), 
                    line, 
                    filepath
                )
                
                if confidence < 0.3:  # Too low confidence, likely false positive
                    continue
                
                # Analyze context
                context = self.context_analyzer.analyze(line, filepath)
                
                # Create result
                result = {
                    "type": self.get_secret_type(),
                    "subtype": pattern_info.get("name", "unknown"),
                    "secret": match.group(),
                    "line": line_num,
                    "file": str(filepath) if filepath else "unknown",
                    "context": line.strip(),
                    "severity": self._calculate_severity(confidence, context),
                    "confidence": confidence,
                    "environment": context["environment"],
                    "risk": self._get_risk_description(),
                    "recommendation": self._get_recommendation(),
                    "commit_hash": commit_hash,
                    "pattern_name": pattern_info.get("name", "unknown"),
                }
                
                # Add hash for deduplication
                result["hash"] = self._calculate_result_hash(result)
                
                results.append(result)
        
        return results
    
    def _calculate_severity(self, confidence: float, context: Dict[str, Any]) -> str:
        """Calculate severity based on confidence and context."""
        env = context["environment"]
        
        if confidence >= 0.9:
            if env == "production":
                return "critical"
            elif env == "staging":
                return "high"
            else:
                return "medium"
        elif confidence >= 0.7:
            if env == "production":
                return "high"
            elif env == "staging":
                return "medium"
            else:
                return "low"
        elif confidence >= 0.5:
            if env == "production":
                return "medium"
            else:
                return "low"
        else:
            return "low"
    
    @abstractmethod
    def _get_risk_description(self) -> str:
        """Return description of the risk if this secret is exposed."""
        pass
    
    @abstractmethod
    def _get_recommendation(self) -> str:
        """Return recommendation for fixing the exposed secret."""
        pass
    
    def _calculate_result_hash(self, result: Dict[str, Any]) -> str:
        """Calculate hash for result deduplication."""
        hash_input = f"{result['type']}:{result['secret']}:{result['file']}:{result['line']}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]