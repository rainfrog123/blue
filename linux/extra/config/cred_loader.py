"""
Credential loader - loads credentials from ~/Documents/cred.json
DO NOT hardcode credentials in code files!
"""

import json
import os
from pathlib import Path


def get_cred_path() -> Path:
    """Get the path to the credentials file."""
    # Windows: ~/Documents/cred.json or ~/Documents/api_cred.json
    # Linux: ~/Documents/cred.json or ~/.config/cred.json
    home = Path.home()
    candidates = [
        home / "Documents" / "api_cred.json",
        home / "Documents" / "cred.json",
        home / ".config" / "cred.json",
        Path("/allah/cred.json"),
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(
        f"Credentials file not found. Looked in: {[str(p) for p in candidates]}"
    )


def load_cred() -> dict:
    """Load all credentials from the JSON file."""
    cred_path = get_cred_path()
    with open(cred_path, "r") as f:
        return json.load(f)


def get_binance() -> dict:
    """Get Binance API credentials."""
    return load_cred()["binance"]


def get_tradingview() -> dict:
    """Get TradingView credentials."""
    return load_cred()["tradingview"]


def get_linode(token_index: int = 0) -> dict:
    """Get Linode credentials. token_index selects which token to use."""
    linode = load_cred()["linode"]
    return {
        "token": linode["tokens"][token_index]
        if token_index < len(linode["tokens"])
        else linode["default_token"],
        "root_password": linode["root_password"],
        "ssr_password": linode["ssr_password"],
    }


def get_linode_token(token_index: int = 0) -> str:
    """Get a specific Linode API token."""
    return get_linode(token_index)["token"]


def get_upstash() -> dict:
    """Get Upstash credentials."""
    return load_cred()["upstash"]


def get_tinder() -> dict:
    """Get Tinder credentials."""
    return load_cred()["tinder"]


def get_proxy_decodo() -> dict:
    """Get Decodo proxy credentials."""
    return load_cred()["proxy"]["decodo"]


def get_proxy_rayobyte() -> dict:
    """Get Rayobyte proxy credentials."""
    return load_cred()["proxy"]["rayobyte"]


def get_ipqs(key_index: int = 0) -> str:
    """Get IPQS API key."""
    ipqs = load_cred()["ipqs"]
    return (
        ipqs["api_keys"][key_index]
        if key_index < len(ipqs["api_keys"])
        else ipqs["default_key"]
    )


def get_alibaba() -> dict:
    """Get Alibaba Cloud credentials."""
    return load_cred()["alibaba"]


if __name__ == "__main__":
    # Test loading
    try:
        cred = load_cred()
        print(f"Loaded credentials from: {get_cred_path()}")
        print(f"Available services: {list(cred.keys())}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
