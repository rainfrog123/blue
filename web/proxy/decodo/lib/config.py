"""
Shared configuration for Decodo SmartProxy scripts (Python)

Usage:
    from lib.config import get_proxy_config, get_ipqs_config
"""

import json
import os
import random
import string
from pathlib import Path
from typing import Optional, Dict, Any


# ============================================
# Credential Loading
# ============================================

def _load_cred_json() -> Optional[Dict[str, Any]]:
    """Load credentials from ~/Documents/cred.json"""
    cred_paths = [
        Path.home() / "Documents" / "cred.json",
        Path.home() / ".config" / "cred.json",
    ]
    
    for cred_path in cred_paths:
        if cred_path.exists():
            with open(cred_path) as f:
                return json.load(f)
    
    return None


def get_decodo_credentials() -> Dict[str, str]:
    """Get Decodo proxy credentials from environment or cred.json"""
    creds = _load_cred_json()
    
    username = os.environ.get("DECODO_USERNAME")
    password = os.environ.get("DECODO_PASSWORD")
    
    if not username and creds:
        username = creds.get("proxy", {}).get("decodo", {}).get("username", "user-sp3j58curv")
    if not password and creds:
        password = creds.get("proxy", {}).get("decodo", {}).get("password")
    
    return {
        "username": username or "user-sp3j58curv",
        "password": password or "SET_DECODO_PASSWORD_ENV"
    }


def get_ipqs_credentials() -> Dict[str, str]:
    """Get IPQS API credentials from environment or cred.json"""
    creds = _load_cred_json()
    
    api_key = os.environ.get("IPQS_API_KEY")
    
    if not api_key and creds:
        api_key = creds.get("ipqs", {}).get("default_key")
    
    return {
        "api_key": api_key or "SET_IPQS_API_KEY_ENV"
    }


# ============================================
# Proxy Configuration
# ============================================

PROXY_CONFIG = {
    "socks5": {
        "host": "gate.decodo.com",
        "port": 7000,
    },
    "https": {
        "host": "gate.decodo.com",
        "port_min": 30001,
        "port_max": 50000,
    }
}

API_ENDPOINTS = {
    "decodo_ip": "https://ip.decodo.com/json",
    "ipqs": "https://ipqualityscore.com/api/json/ip",
}

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"


# ============================================
# Helper Functions
# ============================================

def get_project_root() -> Path:
    """Get the project root directory"""
    return Path(__file__).parent.parent


def get_countries() -> list:
    """Load countries from data/countries.txt"""
    country_file = get_project_root() / "data" / "countries.txt"
    
    if country_file.exists():
        content = country_file.read_text()
        # Parse the Python-style list
        try:
            return eval(content)
        except:
            return []
    
    return []


def get_country_name(prefix: str) -> str:
    """Get country name from country code prefix"""
    countries = get_countries()
    
    for country in countries:
        if country.get("prefix") == prefix:
            return country.get("location", prefix)
    
    return prefix


def generate_session_prefix() -> str:
    """Generate a random session prefix"""
    fruits = ["apple", "banana", "orange", "grape", "kiwi", "mango", "peach", 
              "cherry", "lemon", "lime", "plum", "berry", "melon", "papaya"]
    
    fruit = random.choice(fruits)
    nums = f"{random.randint(0, 99):02d}"
    chars = ''.join(random.choices(string.ascii_lowercase, k=3))
    
    return f"{fruit}{nums}{chars}"


def get_random_https_port() -> int:
    """Get a random port in the HTTPS proxy range"""
    return random.randint(
        PROXY_CONFIG["https"]["port_min"],
        PROXY_CONFIG["https"]["port_max"]
    )


def build_socks5_proxy_url(
    country: str = None,
    session: str = None,
    session_duration: int = 60
) -> str:
    """Build a SOCKS5 proxy URL with authentication"""
    creds = get_decodo_credentials()
    
    auth_parts = [creds["username"]]
    
    if session:
        auth_parts.append(f"session-{session}")
    
    auth_parts.append(f"sessionduration-{session_duration}")
    
    if country:
        auth_parts.append(f"country-{country}")
    
    auth_string = "-".join(auth_parts)
    
    return (
        f"socks5h://{auth_string}:{creds['password']}"
        f"@{PROXY_CONFIG['socks5']['host']}:{PROXY_CONFIG['socks5']['port']}"
    )


def build_https_proxy_url(
    country: str = None,
    session_duration: int = 60,
    port: int = None
) -> str:
    """Build an HTTPS proxy URL with authentication"""
    creds = get_decodo_credentials()
    
    auth_parts = [creds["username"]]
    auth_parts.append(f"sessionduration-{session_duration}")
    
    if country:
        auth_parts.append(f"country-{country}")
    
    auth_string = "-".join(auth_parts)
    
    if port is None:
        port = get_random_https_port()
    
    return (
        f"https://{auth_string}:{creds['password']}"
        f"@{PROXY_CONFIG['https']['host']}:{port}"
    )


def get_score_emoji(score: int) -> str:
    """Get emoji representation of fraud score"""
    if score == 0:
        return "✅✅✅"
    elif score < 20:
        return "✅✅"
    elif score < 40:
        return "✅"
    elif score < 70:
        return "⚠️"
    else:
        return "🚨"


# ============================================
# Compatibility with existing cred_loader
# ============================================

def get_proxy_decodo() -> Dict[str, str]:
    """Compatibility function for existing code using cred_loader"""
    return get_decodo_credentials()
