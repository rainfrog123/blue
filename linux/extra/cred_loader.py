"""
Credential loader - loads credentials from blue/cred.json
DO NOT hardcode credentials in code files!
"""

import json
from functools import lru_cache
from pathlib import Path

# Credential file path: blue/cred.json (relative to this file)
CRED_PATH = Path(__file__).resolve().parent.parent.parent / "cred.json"


@lru_cache(maxsize=1)
def load_cred() -> dict:
    """Load all credentials from the JSON file (cached)."""
    if not CRED_PATH.exists():
        raise FileNotFoundError(f"Credentials file not found: {CRED_PATH}")
    with open(CRED_PATH, "r") as f:
        return json.load(f)


def reload_cred() -> dict:
    """Force reload credentials (clears cache)."""
    load_cred.cache_clear()
    return load_cred()


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


def get_hero_sms() -> dict:
    """Get HeroSMS credentials."""
    return load_cred()["hero_sms"]


def get_cloudflare() -> dict:
    """Get Cloudflare credentials."""
    return load_cred()["cloudflare"]


def get_cloudflare_api_token() -> str:
    """Get Cloudflare API token."""
    cred = load_cred()
    # Support both formats
    if "cloudflare" in cred:
        return cred["cloudflare"]["api_token"]
    return cred.get("CLOUDFLARE_API_TOKEN", "")


def get_azure() -> dict:
    """Get Azure service principal credentials."""
    return load_cred()["azure"]


if __name__ == "__main__":
    # Test loading
    try:
        cred = load_cred()
        print(f"Loaded credentials from: {CRED_PATH}")
        print(f"Available services: {list(cred.keys())}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
