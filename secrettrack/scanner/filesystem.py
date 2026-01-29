import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
import fnmatch

from secrettrack.detectors.base import BaseDetector
from secrettrack.detectors.aws import AWSDetector
from secrettrack.detectors.github import GitHubDetector
from secrettrack.detectors.stripe import StripeDetector
from secrettrack.detectors.firebase import FirebaseDetector
from secrettrack.detectors.generic import GenericDetector


class FileSystemScanner:
    """Scans filesystem for files containing secrets."""
    
    # Files to always skip
    DEFAULT_SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",  # Images
        ".mp4", ".mp3", ".avi", ".mkv", ".mov",  # Media
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",  # Documents
        ".zip", ".tar", ".gz", ".7z", ".rar",  # Archives
        ".exe", ".dll", ".so", ".dylib",  # Binaries
    }
    
    # Maximum file size to scan (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        self.exclude_patterns = exclude_patterns or []
        self.detectors = self._initialize_detectors()
    
    def _initialize_detectors(self) -> List[BaseDetector]:
        """Initialize all available detectors."""
        return [
            AWSDetector(),
            GitHubDetector(),
            StripeDetector(),
            FirebaseDetector(),
            GenericDetector(),
        ]
    
    def _should_scan_file(self, filepath: Path) -> bool:
        """Check if a file should be scanned."""
        # Check file size
        try:
            if filepath.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except OSError:
            return False
        
        # Check extension
        if filepath.suffix.lower() in self.DEFAULT_SKIP_EXTENSIONS:
            return False
        
        # Check exclude patterns
        file_str = str(filepath)
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(file_str, pattern):
                return False
            if fnmatch.fnmatch(file_str, f"*/{pattern}"):
                return False
            if fnmatch.fnmatch(file_str, f"**/{pattern}"):
                return False
        
        return True
    
    def _read_file_lines(self, filepath: Path) -> List[str]:
        """Read file lines with proper encoding handling."""
        try:
            # Try UTF-8 first
            with open(filepath, "r", encoding="utf-8") as f:
                return f.readlines()
        except UnicodeDecodeError:
            try:
                # Try Latin-1 as fallback
                with open(filepath, "r", encoding="latin-1") as f:
                    return f.readlines()
            except:
                return []
        except Exception:
            return []
    
    def scan(self, path: Path) -> List[Dict[str, Any]]:
        """Scan a path for secrets."""
        results = []
        
        if path.is_file():
            files_to_scan = [path]
        else:
            files_to_scan = self._find_files(path)
        
        for filepath in files_to_scan:
            if not self._should_scan_file(filepath):
                continue
            
            file_results = self._scan_file(filepath)
            results.extend(file_results)
        
        return results
    
    def _find_files(self, directory: Path) -> Generator[Path, None, None]:
        """Find all files in directory recursively."""
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            root_path = Path(root)
            for pattern in self.exclude_patterns:
                if any(fnmatch.fnmatch(str(root_path / d), f"*/{pattern}") for d in dirs):
                    dirs[:] = [d for d in dirs if not fnmatch.fnmatch(str(root_path / d), f"*/{pattern}")]
            
            for file in files:
                yield root_path / file
    
    def _scan_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Scan a single file for secrets."""
        results = []
        lines = self._read_file_lines(filepath)
        
        if not lines:
            return results
        
        for line_num, line in enumerate(lines, 1):
            for detector in self.detectors:
                detector_results = detector.scan_line(line, line_num, filepath)
                if detector_results:
                    results.extend(detector_results)
        
        return results