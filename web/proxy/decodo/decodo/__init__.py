"""
Decodo SmartProxy Client Library

A Python client for Decodo residential proxy service with IPQS fraud scoring.
"""

from .client import DecodoClient
from .scanner import SessionScanner
from .ipqs import IPQSChecker

__version__ = "1.0.0"
__all__ = ["DecodoClient", "SessionScanner", "IPQSChecker"]
