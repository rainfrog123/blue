#!/usr/bin/env python3
"""
IPQS (IP Quality Score) API client
Checks IP reputation, fraud score, VPN/proxy detection
"""

import sys
from pathlib import Path
import requests

# Add cred_loader to path (clash -> octo -> auto -> web -> blue -> linux/extra)
sys.path.insert(0, str(Path(__file__).parents[4] / "linux" / "extra"))
from cred_loader import get_ipqs

# IPQS API endpoint
IPQS_API = "https://ipqualityscore.com/api/json/ip"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


def get_score_emoji(score: int) -> str:
    """Get emoji for fraud score"""
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


def check_ip(ip_address: str = None, timeout: int = 15) -> dict | None:
    """
    Check IP reputation using IPQS API.
    If no IP provided, checks current public IP.
    
    Returns dict with:
        - ip, country, countryCode, city, region
        - isp, org, asn
        - fraudScore, proxy, vpn, tor, bot
        - isResidential (connection_type == 'Residential')
    """
    # If no IP provided, first get current IP using ip-api.com (more reliable with proxies)
    if ip_address is None:
        try:
            # Try ip-api.com first (HTTP, works better with proxies)
            resp = requests.get("http://ip-api.com/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    ip_address = data.get("query")
                else:
                    return {"error": f"ip-api failed: {data.get('message')}"}
            else:
                return {"error": f"Failed to get current IP: HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": f"Failed to get current IP: {e}"}
    
    try:
        api_key = get_ipqs()
        url = f"{IPQS_API}/{api_key}/{ip_address}"
        params = {
            'strictness': 1,
            'user_agent': DEFAULT_USER_AGENT,
            'user_language': 'en-US',
            'fast': 'true',
            'mobile': 'false'
        }
        
        resp = requests.get(url, params=params, timeout=timeout)
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        
        data = resp.json()
        
        if not data.get('success'):
            return {"error": data.get('message', 'API error')}
        
        # Normalize response
        return {
            "ip": ip_address,
            "country": data.get("country_code"),
            "countryCode": data.get("country_code"),
            "city": data.get("city"),
            "region": data.get("region"),
            "isp": data.get("ISP"),
            "org": data.get("organization"),
            "asn": data.get("ASN"),
            "fraudScore": data.get("fraud_score"),
            "proxy": data.get("proxy"),
            "vpn": data.get("vpn"),
            "tor": data.get("tor"),
            "bot": data.get("bot_status"),
            "recentAbuse": data.get("recent_abuse"),
            "isResidential": data.get("connection_type") == "Residential",
            "connectionType": data.get("connection_type"),
        }
        
    except requests.Timeout:
        return {"error": "Request timeout"}
    except Exception as e:
        return {"error": str(e)}


def get_fraud_emoji(score: int) -> str:
    """Get emoji for fraud score"""
    return get_score_emoji(score)


def print_report(info: dict):
    """Print formatted IP report"""
    if "error" in info:
        print(f"Error: {info['error']}")
        return
    
    score = info.get('fraudScore', 0)
    emoji = get_fraud_emoji(score)
    
    print(f"IP: {info.get('ip')}")
    print(f"Location: {info.get('city')}, {info.get('region')}, {info.get('country')}")
    print(f"ISP: {info.get('isp')}")
    print(f"Org: {info.get('org')}")
    print(f"ASN: {info.get('asn')}")
    print(f"Fraud Score: {emoji} {score}/100")
    print(f"Proxy: {info.get('proxy')} | VPN: {info.get('vpn')} | TOR: {info.get('tor')}")
    print(f"Residential: {info.get('isResidential')} ({info.get('connectionType')})")


# Quick test
if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    
    print("Checking IP..." if ip is None else f"Checking {ip}...")
    info = check_ip(ip)
    print()
    print_report(info)
