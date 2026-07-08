#!/usr/bin/env python3
"""Apply catch-all forward to Proton on hyas.space and hyas.site."""

import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "infra/scripts"))
from cred_loader import get_cloudflare  # noqa: E402

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = "5d75ad91bc621086a1908973590051c3"
DEST_EMAIL = "b7aba857257b9652@protonmail.com"
ZONES = {
    "hyas.space": "14a1737c5a43cdff29c09a606c162316",
    "hyas.site": "2c5bc584bd4a638c9b6a36a85dc591cb",
}


def headers():
    cf = get_cloudflare()
    if cf.get("api_token"):
        return {
            "Authorization": f"Bearer {cf['api_token']}",
            "Content-Type": "application/json",
        }
    return {
        "X-Auth-Email": cf["email"],
        "X-Auth-Key": cf["global_api_key"],
        "Content-Type": "application/json",
    }


def api(method, path, **kwargs):
    r = requests.request(method, f"{API}{path}", headers=headers(), timeout=30, **kwargs)
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(f"{method} {path}: {data.get('errors', data)}")
    return data.get("result")


def ensure_destination():
    addrs = api("GET", f"/accounts/{ACCOUNT_ID}/email/routing/addresses") or []
    for a in addrs:
        if a.get("email") == DEST_EMAIL:
            return a
    return api(
        "POST",
        f"/accounts/{ACCOUNT_ID}/email/routing/addresses",
        json={"email": DEST_EMAIL},
    )


def apply_catchall(zone_id: str):
    return api(
        "PUT",
        f"/zones/{zone_id}/email/routing/rules/catch_all",
        json={
            "matchers": [{"type": "all"}],
            "actions": [{"type": "forward", "value": [DEST_EMAIL]}],
            "enabled": True,
            "name": "Catch-all forward to Proton",
        },
    )


def main():
    addr = ensure_destination()
    if not addr.get("verified"):
        print(
            f"Destination {DEST_EMAIL} is not verified yet.\n"
            "Check Proton inbox for Cloudflare verification email and click the link,\n"
            "then run this script again."
        )
        print(json.dumps(addr, indent=2))
        sys.exit(1)

    for domain, zone_id in ZONES.items():
        rule = apply_catchall(zone_id)
        print(f"OK {domain}: {rule.get('actions')}")

    print("Done. Both zones catch-all ->", DEST_EMAIL)


if __name__ == "__main__":
    main()
