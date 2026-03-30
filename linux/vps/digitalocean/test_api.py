#!/usr/bin/env python3
"""Test DigitalOcean API connectivity and explore available resources."""

import json
import sys
from pathlib import Path

import requests

CRED_PATH = Path("/allah/blue/cred.json")
BASE_URL = "https://api.digitalocean.com/v2"


def load_token() -> str:
    """Load DO token from cred.json."""
    with open(CRED_PATH) as f:
        creds = json.load(f)
    return creds["digitalocean"]["token"]


def api_get(endpoint: str, token: str) -> dict:
    """Make GET request to DO API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resp = requests.get(f"{BASE_URL}/{endpoint}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def main():
    print("=" * 60)
    print("DigitalOcean API Test")
    print("=" * 60)

    token = load_token()
    print(f"Token loaded: {token[:20]}...")

    # 1. Account info
    print("\n[1] Account Info")
    print("-" * 40)
    account = api_get("account", token)["account"]
    print(f"  Email: {account['email']}")
    print(f"  Status: {account['status']}")
    print(f"  Droplet Limit: {account['droplet_limit']}")
    print(f"  Email Verified: {account['email_verified']}")

    # 2. List droplets
    print("\n[2] Droplets")
    print("-" * 40)
    droplets = api_get("droplets", token)["droplets"]
    if droplets:
        for d in droplets:
            ip = d["networks"]["v4"][0]["ip_address"] if d["networks"]["v4"] else "N/A"
            print(f"  - {d['name']} ({d['size_slug']}) | {d['region']['slug']} | {ip} | {d['status']}")
    else:
        print("  No droplets found")

    # 3. List regions
    print("\n[3] Available Regions")
    print("-" * 40)
    regions = api_get("regions", token)["regions"]
    available = [r for r in regions if r["available"]]
    print(f"  {len(available)} regions available:")
    for r in available[:8]:
        print(f"    - {r['slug']:8} | {r['name']}")
    if len(available) > 8:
        print(f"    ... and {len(available) - 8} more")

    # 4. List SSH keys
    print("\n[4] SSH Keys")
    print("-" * 40)
    keys = api_get("account/keys", token)["ssh_keys"]
    if keys:
        for k in keys:
            print(f"  - {k['name']} (id: {k['id']})")
    else:
        print("  No SSH keys registered")

    # 5. List sizes (instance types)
    print("\n[5] Popular Droplet Sizes")
    print("-" * 40)
    sizes = api_get("sizes", token)["sizes"]
    available_sizes = [s for s in sizes if s["available"]][:10]
    for s in available_sizes:
        print(f"  - {s['slug']:20} | {s['vcpus']} vCPU | {s['memory']/1024:.0f}GB RAM | ${s['price_monthly']}/mo")

    # 6. List projects
    print("\n[6] Projects")
    print("-" * 40)
    projects = api_get("projects", token)["projects"]
    for p in projects:
        print(f"  - {p['name']} ({p['environment']}) | default: {p['is_default']}")

    # 7. Balance
    print("\n[7] Account Balance")
    print("-" * 40)
    balance = api_get("customers/my/balance", token)
    print(f"  Month-to-date usage: ${balance['month_to_date_usage']}")
    print(f"  Account balance: ${balance['account_balance']}")

    print("\n" + "=" * 60)
    print("API test completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
