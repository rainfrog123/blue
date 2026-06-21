#!/usr/bin/env python3
"""Test set-hard-limit endpoint directly."""
import json
from pathlib import Path
import requests

BASE = "https://cursor.com"

def load_cookies(path: Path) -> dict:
    with open(path) as f:
        data = json.load(f)
    return {c["name"]: c["value"] for c in data}

def main():
    cookies = load_cookies(Path(__file__).parent / "cookies")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Origin": BASE,
        "Referer": f"{BASE}/dashboard/billing",
    }
    
    # First get current hard limit
    print("=== Getting current hard limit ===")
    r = requests.post(f"{BASE}/api/dashboard/get-hard-limit", 
                      json={}, cookies=cookies, headers=headers)
    print(f"Current: {r.status_code} | {r.text}")
    
    print("\n=== Testing set-hard-limit endpoint ===")
    
    # Test various payloads for set-hard-limit
    payloads = [
        {},
        {"hardLimitCents": 9999900},  # $99999
        {"hardLimit": 99999},
        {"limitCents": 9999900},
        {"limit": 99999},
        {"value": 9999900},
        {"amount": 9999900},
        {"spendingLimitCents": 9999900},
        {"cents": 9999900},
    ]
    
    for payload in payloads:
        r = requests.post(f"{BASE}/api/dashboard/set-hard-limit",
                         json=payload, cookies=cookies, headers=headers)
        flag = ""
        if r.status_code == 200 and "error" not in r.text.lower():
            flag = " [!!!]"
        print(f"\nPayload: {payload}")
        print(f"  {r.status_code} | {r.text[:200]}{flag}")
    
    # Check if limit changed
    print("\n=== Checking if limit changed ===")
    r = requests.post(f"{BASE}/api/dashboard/get-hard-limit", 
                      json={}, cookies=cookies, headers=headers)
    print(f"After: {r.status_code} | {r.text}")

if __name__ == "__main__":
    main()
