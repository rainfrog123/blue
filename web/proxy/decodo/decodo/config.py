"""
Configuration for Decodo proxy and IPQS services.

Loads credentials from environment variables or ~/Documents/cred.json
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


# ============================================
# Constants
# ============================================

DECODO_IP_API = "https://ip.decodo.com/json"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"


# ============================================
# Configuration Classes
# ============================================

@dataclass
class ProxyConfig:
    """Decodo proxy configuration."""
    host: str = "gate.decodo.com"
    port_min: int = 30001
    port_max: int = 50000
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
    """Load credentials from /allah/blue/cred.json or fallback paths."""
    cred_paths = [
        Path("/allah/blue/cred.json"),
        Path.home() / "Documents" / "cred.json",
        Path.home() / ".config" / "cred.json",
    ]
    
    for cred_path in cred_paths:
        if cred_path.exists():
            with open(cred_path) as f:
                return json.load(f)
    
    return None


def get_proxy_config() -> ProxyConfig:
    """Get Decodo proxy configuration with credentials."""
    creds = _load_cred_json()
    
    username = os.environ.get("DECODO_USERNAME")
    password = os.environ.get("DECODO_PASSWORD")
    
    if not username and creds:
        username = creds.get("proxy", {}).get("decodo", {}).get("username", "")
    if not password and creds:
        password = creds.get("proxy", {}).get("decodo", {}).get("password", "")
    
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

def build_proxy_url(
    country: Optional[str] = None,
    session_duration: int = 60,
    session: Optional[str] = None,
    port: Optional[int] = None,
) -> str:
    """
    Build HTTPS proxy URL with authentication.
    
    Args:
        country: Country code (e.g., "gb", "us")
        session_duration: Session duration in minutes
        session: Session name for sticky sessions
        port: Specific port (random if not provided)
        
    Returns:
        Proxy URL in format: https://user-{username}-...:{password}@{country}.decodo.com:{port}
    """
    import random
    
    config = get_proxy_config()
    
    # Build username with options: user-{username}-session-{session}-sessionduration-{duration}
    auth_parts = [f"user-{config.username}"]
    
    if session:
        auth_parts.append(f"session-{session}")
    
    auth_parts.append(f"sessionduration-{session_duration}")
    
    auth_string = "-".join(auth_parts)
    
    # Use random port if not specified
    if port is None:
        port = random.randint(config.port_min, config.port_max)
    
    # Host format: {country}.decodo.com
    host = f"{country}.decodo.com" if country else "gate.decodo.com"
    
    return f"https://{auth_string}:{config.password}@{host}:{port}"
