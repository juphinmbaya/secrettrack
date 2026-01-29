import re
from pathlib import Path
from typing import Dict, Any, Optional


class ContextAnalyzer:
    """Analyzes the context of a potential secret."""
    
    # Keywords indicating environment
    DEV_KEYWORDS = {"dev", "development", "test", "local", "staging", "qa", "sandbox"}
    PROD_KEYWORDS = {"prod", "production", "live", "real", "master", "main"}
    
    # File patterns
    CONFIG_FILES = {".env", "config.json", "settings.py", "configuration.yml", 
                    "application.properties", "appsettings.json"}
    
    def analyze(self, line: str, filepath: Optional[Path]) -> Dict[str, Any]:
        """Analyze the context of a line containing a potential secret."""
        environment = self._detect_environment(line, filepath)
        
        return {
            "environment": environment,
            "file_type": self._get_file_type(filepath),
            "is_config_file": self._is_config_file(filepath),
            "line_context": line.strip()[:100],  # First 100 chars
        }
    
    def _detect_environment(self, line: str, filepath: Optional[Path]) -> str:
        """Detect the environment (dev, staging, prod)."""
        text_to_check = line.lower()
        
        if filepath:
            text_to_check += " " + str(filepath).lower()
        
        # Check for production indicators
        for keyword in self.PROD_KEYWORDS:
            if keyword in text_to_check:
                return "production"
        
        # Check for development indicators
        for keyword in self.DEV_KEYWORDS:
            if keyword in text_to_check:
                return "staging"
        
        # Default to staging for safety
        return "staging"
    
    def _get_file_type(self, filepath: Optional[Path]) -> str:
        """Get the type of file."""
        if not filepath:
            return "unknown"
        
        suffix = filepath.suffix.lower()
        
        if suffix in {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"}:
            return "source_code"
        elif suffix in {".json", ".yml", ".yaml", ".xml", ".toml"}:
            return "configuration"
        elif suffix in {".md", ".txt", ".rst"}:
            return "documentation"
        elif suffix in {".sh", ".bat", ".ps1"}:
            return "script"
        else:
            return "other"
    
    def _is_config_file(self, filepath: Optional[Path]) -> bool:
        """Check if file is a configuration file."""
        if not filepath:
            return False
        
        filename = filepath.name.lower()
        return any(config_file in filename for config_file in self.CONFIG_FILES) or filepath.suffix in {".env", ".properties", ".cfg", ".conf"}