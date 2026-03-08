"""
Configuration for IPRoyal proxy and IPQS services.

Loads credentials from environment variables or ~/Documents/cred.json
"""

import json
import os
import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


# ============================================
# Constants
# ============================================

IP_CHECK_API = "https://api.ipify.org?format=json"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"


# ============================================
# Configuration Classes
# ============================================

@dataclass
class ProxyConfig:
    """IPRoyal proxy configuration."""
    host: str = "geo.iproyal.com"
    port: int = 11203
    username: str = ""
    password: str = ""


@dataclass
class IPQSConfig:
    """IPQS API configuration."""
    base_url: str = "https://ipqualityscore.com/api/json/ip"
    api_key: str = ""
    strictness: int = 1


# ============================================
# Credential Loading
# ============================================

def _load_cred_json() -> Optional[Dict[str, Any]]:
    """Load credentials from standard locations."""
    cred_paths = [
        Path("/allah/blue/cred.json"),
        Path.home() / "blue" / "cred.json",
        Path.home() / "Documents" / "cred.json",
        Path.home() / ".config" / "cred.json",
    ]
    
    for cred_path in cred_paths:
        if cred_path.exists():
            with open(cred_path) as f:
                return json.load(f)
    
    return None


def get_proxy_config() -> ProxyConfig:
    """Get IPRoyal proxy configuration with credentials."""
    creds = _load_cred_json()
    
    username = os.environ.get("IPROYAL_USERNAME")
    password = os.environ.get("IPROYAL_PASSWORD")
    
    if not username and creds:
        username = creds.get("proxy", {}).get("iproyal", {}).get("username", "")
    if not password and creds:
        password = creds.get("proxy", {}).get("iproyal", {}).get("password", "")
    
    return ProxyConfig(
        username=username or "",
        password=password or "",
    )


def get_ipqs_config() -> IPQSConfig:
    """Get IPQS API configuration with credentials."""
    creds = _load_cred_json()
    
    api_key = os.environ.get("IPQS_API_KEY")
    
    if not api_key and creds:
        api_key = creds.get("ipqs", {}).get("default_key", "")
    
    return IPQSConfig(
        api_key=api_key or "",
    )


# ============================================
# Proxy URL Builder
# ============================================

def generate_session_id(length: int = 8) -> str:
    """Generate a random session ID."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def build_proxy_url(
    country: str = "de",
    session: Optional[str] = None,
    lifetime: str = "1h",
    skip_isp_static: bool = True,
) -> str:
    """
    Build SOCKS5 proxy URL with authentication for IPRoyal.
    
    IPRoyal format:
        socks5://{username}:{password}_country-{country}_session-{session}_lifetime-{lifetime}_skipispstatic-1@geo.iproyal.com:11203
    
    Args:
        country: Country code (e.g., "de", "gb", "us")
        session: Session ID for sticky sessions (auto-generated if None)
        lifetime: Session lifetime (e.g., "1h", "24h", "1m" for 1 minute)
        skip_isp_static: Skip static ISP IPs (default: True)
        
    Returns:
        Proxy URL ready to use with requests
    """
    config = get_proxy_config()
    
    if session is None:
        session = generate_session_id()
    
    # Build password with options
    password_parts = [
        config.password,
        f"country-{country}",
        f"session-{session}",
        f"lifetime-{lifetime}",
    ]
    
    if skip_isp_static:
        password_parts.append("skipispstatic-1")
    
    full_password = "_".join(password_parts)
    
    return f"socks5://{config.username}:{full_password}@{config.host}:{config.port}"
