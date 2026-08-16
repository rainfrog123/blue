#!/usr/bin/env python3
"""Deep probe actions that returned 500 - try various arg structures."""
import json
import sys
from pathlib import Path

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

def test(cookies, headers, payload):
    try:
        r = requests.post(URL, json=payload, cookies=cookies, headers=headers, timeout=15)
        return r.status_code, r.text[:300]
    except Exception as e:
        return -1, str(e)

def main():
    cookies = load_cookies(Path(__file__).parent / "cookies")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Origin": BASE,
        "Referer": f"{BASE}/dashboard/billing",
    }
    
    user_id = "user_01KHTHPRT0QDGRGJ4P89FG72KK"
    
    # Test various arg structures for 500-returning actions
    tests = [
        # setHardLimit variations
        ("setHardLimit", {}),
        ("setHardLimit", {"value": 9999999}),
        ("setHardLimit", {"hardLimit": 9999999}),
        ("setHardLimit", {"hardLimitCents": 9999999}),
        ("setHardLimit", {"cents": 9999999}),
        ("setHardLimit", {"limit": 9999999}),
        ("setHardLimit", {"amount": 9999999}),
        ("setHardLimit", {"userId": user_id, "hardLimitCents": 9999999}),
        ("setHardLimit", {"teamId": -1, "hardLimitCents": 9999999}),
        
        # addCredits variations  
        ("addCredits", {}),
        ("addCredits", {"amount": 10000}),
        ("addCredits", {"cents": 10000}),
        ("addCredits", {"credits": 10000}),
        ("addCredits", {"value": 10000}),
        ("addCredits", {"amountCents": 10000}),
        ("addCredits", {"userId": user_id, "amount": 10000}),
        
        # setCredits variations
        ("setCredits", {}),
        ("setCredits", {"balance": 10000}),
        ("setCredits", {"amount": 10000}),
        ("setCredits", {"credits": 10000}),
        
        # updateUsage variations
        ("updateUsage", {}),
        ("updateUsage", {"used": 0}),
        ("updateUsage", {"usage": 0}),
        ("updateUsage", {"value": 0}),
        ("updateUsage", {"reset": True}),
        
        # setUsage variations
        ("setUsage", {}),
        ("setUsage", {"value": 0}),
        ("setUsage", {"used": 0}),
        ("setUsage", {"usage": 0}),
        
        # grantCredits variations
        ("grantCredits", {}),
        ("grantCredits", {"amount": 10000}),
        ("grantCredits", {"amountCents": 10000}),
        ("grantCredits", {"userId": user_id, "amount": 10000}),
        
        # addCreditGrant variations
        ("addCreditGrant", {}),
        ("addCreditGrant", {"amount": 10000}),
        ("addCreditGrant", {"amountCents": 10000}),
        ("addCreditGrant", {"creditGrantId": "test", "amount": 10000}),
    ]
    
    print("=" * 80)
    print("Probing 500-returning actions with various arg structures")
    print("=" * 80)
    
    for action, args in tests:
        payload = {"action": action, "args": args}
        status, text = test(cookies, headers, payload)
        
        flag = ""
        if status == 200 and "error" not in text.lower() and "Unknown" not in text:
            flag = " [!!! SUCCESS !!!]"
        elif status != 500:
            flag = f" [status changed!]"
            
        print(f"\n{action} args={json.dumps(args)[:50]}:")
        print(f"  status={status} | {text[:150]!r}{flag}")

    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()
