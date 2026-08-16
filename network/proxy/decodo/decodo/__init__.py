"""Decodo proxy toolkit — client, sticky sessions, IPQS scanner."""

from .client import DecodoClient, ExitInfo, ProxySession, StickySession
from .config import (
    build_proxy_url,
    get_decodo_api_key,
    get_proxy_config,
    validate_session_id,
)
from .ipqs import IPQSChecker, IPQSResult
from .scanner import ScanResult, ScanSummary, SessionScanner

__version__ = "2.0.0"
__all__ = [
    "DecodoClient",
    "ExitInfo",
    "ProxySession",
    "StickySession",
    "build_proxy_url",
    "get_proxy_config",
    "get_decodo_api_key",
    "validate_session_id",
    "IPQSChecker",
    "IPQSResult",
    "SessionScanner",
    "ScanResult",
    "ScanSummary",
]
