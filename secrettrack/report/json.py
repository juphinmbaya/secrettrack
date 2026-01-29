import json
from typing import List, Dict, Any


class JSONReport:
    """Generates JSON reports for CI/CD integration."""
    
    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results
    
    def generate(self) -> str:
        """Generate JSON report."""
        # Remove sensitive data and add metadata
        safe_results = []
        for result in self.results:
            safe_result = {
                "type": result.get("type"),
                "subtype": result.get("subtype"),
                "severity": result.get("severity"),
                "file": result.get("file"),
                "line": result.get("line"),
                "environment": result.get("environment"),
                "confidence": result.get("confidence"),
                "risk": result.get("risk"),
                "recommendation": result.get("recommendation"),
                "hash": result.get("hash"),
                "context_preview": result.get("context", "")[:100],
                "secret_preview": self._mask_secret(result.get("secret", "")),
            }
            safe_results.append(safe_result)
        
        report = {
            "metadata": {
                "tool": "secretshunter",
                "version": "1.0.0",
                "scan_timestamp": self._get_timestamp(),
            },
            "summary": {
                "total_findings": len(safe_results),
                "critical": len([r for r in safe_results if r.get("severity") == "critical"]),
                "high": len([r for r in safe_results if r.get("severity") == "high"]),
                "medium": len([r for r in safe_results if r.get("severity") == "medium"]),
                "low": len([r for r in safe_results if r.get("severity") == "low"]),
            },
            "findings": safe_results,
        }
        
        return json.dumps(report, indent=2)
    
    def _mask_secret(self, secret: str) -> str:
        """Mask secret for safe JSON output."""
        if not secret:
            return ""
        if len(secret) <= 4:
            return "****"
        return secret[:2] + "****" + secret[-2:]
    
    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"