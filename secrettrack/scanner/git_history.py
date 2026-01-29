import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
import os

from secrettrack.detectors.base import BaseDetector
from secrettrack.detectors.aws import AWSDetector
from secrettrack.detectors.github import GitHubDetector
from secrettrack.detectors.stripe import StripeDetector
from secrettrack.detectors.firebase import FirebaseDetector
from secrettrack.detectors.generic import GenericDetector


class GitHistoryScanner:
    """Scans Git history for secrets."""
    
    def __init__(self):
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
    
    def scan(self, repo_path: Path) -> List[Dict[str, Any]]:
        """Scan Git repository history for secrets."""
        if not self._is_git_repo(repo_path):
            return []
        
        results = []
        
        # Get all commits
        commits = self._get_commits(repo_path)
        
        for commit in commits:
            commit_results = self._scan_commit(repo_path, commit)
            results.extend(commit_results)
        
        return results
    
    def _is_git_repo(self, path: Path) -> bool:
        """Check if path is a Git repository."""
        git_dir = path / ".git"
        return git_dir.exists() and git_dir.is_dir()
    
    def _get_commits(self, repo_path: Path) -> List[str]:
        """Get list of commit hashes."""
        try:
            result = subprocess.run(
                ["git", "log", "--pretty=format:%H"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.strip().split("\n") if result.stdout else []
        except (subprocess.SubprocessError, FileNotFoundError):
            return []
    
    def _scan_commit(self, repo_path: Path, commit_hash: str) -> List[Dict[str, Any]]:
        """Scan a specific commit for secrets."""
        results = []
        
        # Get diff for this commit
        diff = self._get_commit_diff(repo_path, commit_hash)
        
        # Parse diff and scan each line
        current_file = None
        line_num = 0
        
        for line in diff.split("\n"):
            # Check for file header
            if line.startswith("+++ b/"):
                current_file = line[6:]  # Remove "+++ b/" prefix
                line_num = 0
            elif line.startswith("+") and not line.startswith("++"):
                # Added line
                line_num += 1
                line_content = line[1:]  # Remove "+" prefix
                
                for detector in self.detectors:
                    detector_results = detector.scan_line(
                        line_content, 
                        line_num, 
                        Path(current_file) if current_file else None,
                        commit_hash=commit_hash
                    )
                    if detector_results:
                        results.extend(detector_results)
        
        return results
    
    def _get_commit_diff(self, repo_path: Path, commit_hash: str) -> str:
        """Get diff for a specific commit."""
        try:
            result = subprocess.run(
                ["git", "show", commit_hash],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout if result.stdout else ""
        except subprocess.SubprocessError:
            return ""