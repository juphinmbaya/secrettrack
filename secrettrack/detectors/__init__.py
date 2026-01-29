"""
Detectors module for identifying specific types of secrets.
"""

from .base import BaseDetector
from .aws import AWSDetector
from .github import GitHubDetector
from .stripe import StripeDetector
from .firebase import FirebaseDetector
from .generic import GenericDetector

__all__ = [
    "BaseDetector",
    "AWSDetector",
    "GitHubDetector",
    "StripeDetector",
    "FirebaseDetector",
    "GenericDetector",
]