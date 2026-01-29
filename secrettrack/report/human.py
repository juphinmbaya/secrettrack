import sys
from typing import List, Dict, Any
from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)


class HumanReport:
    """Generates human-readable console reports."""
    
    SEVERITY_COLORS = {
        "critical": Fore.RED + Style.BRIGHT,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.BLUE,
    }
    
    SEVERITY_ICONS = {
        "critical": "🔥",
        "high": "⚠️",
        "medium": "🔸",
        "low": "ℹ️",
    }
    
    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results
        self._group_results()
    
    def _group_results(self):
        """Group results by severity."""
        self.grouped_results = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
        
        for result in self.results:
            severity = result.get("severity", "low").lower()
            self.grouped_results.get(severity, []).append(result)
    
    def generate(self) -> str:
        """Generate human-readable report."""
        if not self.results:
            return f"{Fore.GREEN}✅ No secrets found!"
        
        output = []
        output.append(f"\n{Style.BRIGHT}🔐 Secrets Hunter Report")
        output.append("=" * 60)
        
        # Summary
        total = len(self.results)
        critical = len(self.grouped_results["critical"])
        high = len(self.grouped_results["high"])
        medium = len(self.grouped_results["medium"])
        low = len(self.grouped_results["low"])
        
        output.append(f"\n{Style.BRIGHT}📊 Summary:")
        output.append(f"  Total findings: {total}")
        output.append(f"  {self.SEVERITY_COLORS['critical']}Critical: {critical}")
        output.append(f"  {self.SEVERITY_COLORS['high']}High: {high}")
        output.append(f"  {self.SEVERITY_COLORS['medium']}Medium: {medium}")
        output.append(f"  {self.SEVERITY_COLORS['low']}Low: {low}")
        
        # Detailed findings by severity
        for severity in ["critical", "high", "medium", "low"]:
            results = self.grouped_results[severity]
            if results:
                output.append(f"\n{self.SEVERITY_ICONS[severity]} "
                            f"{self.SEVERITY_COLORS[severity]}{severity.upper()} "
                            f"Findings ({len(results)}):")
                output.append("-" * 40)
                
                for result in results[:10]:  # Limit to 10 per severity
                    output.append(self._format_result(result))
                
                if len(results) > 10:
                    output.append(f"  ... and {len(results) - 10} more")
        
        # Recommendations section
        output.append(f"\n{Style.BRIGHT}🛡️  Security Recommendations:")
        output.append("-" * 40)
        
        if critical > 0:
            output.append(f"{Fore.RED}❌ CRITICAL ACTION REQUIRED:")
            output.append("  • Rotate compromised credentials IMMEDIATELY")
            output.append("  • Check for unauthorized access")
            output.append("  • Remove secrets from git history")
        
        output.append(f"{Fore.YELLOW}🔧 General recommendations:")
        output.append("  • Use environment variables for secrets")
        output.append("  • Implement a secrets management solution")
        output.append("  • Add pre-commit hooks to prevent future leaks")
        output.append("  • Educate team on secure coding practices")
        
        return "\n".join(output)
    
    def _format_result(self, result: Dict[str, Any]) -> str:
        """Format a single result for display."""
        severity = result.get("severity", "low").lower()
        color = self.SEVERITY_COLORS.get(severity, Fore.WHITE)
        icon = self.SEVERITY_ICONS.get(severity, "•")
        
        lines = [
            f"{color}{icon} {result['type'].upper()}: {result.get('subtype', 'unknown')}",
            f"  File: {result['file']}:{result['line']}",
            f"  Secret: {self._mask_secret(result['secret'])}",
            f"  Environment: {result.get('environment', 'unknown')}",
            f"  Risk: {result.get('risk', 'Unknown risk')}",
            f"  Action: {result.get('recommendation', 'Investigate immediately')}",
        ]
        
        return "\n".join(lines)
    
    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display."""
        if len(secret) <= 8:
            return "***"
        
        return secret[:4] + "***" + secret[-4:] if len(secret) > 8 else "***"