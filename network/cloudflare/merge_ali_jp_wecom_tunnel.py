#!/usr/bin/env python3
"""Merge wecom.hyas.space into ali-jp tunnel ingress without wiping ajp.* routes."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cli import api_request, load_config  # noqa: E402

TUNNEL_ID = "1aff6c07-00d0-48a0-ad6e-accfae40a5c1"
HOSTNAME = "wecom.hyas.space"
SERVICE = "http://wecom-verify:8080"
ZONE_HYAS_SPACE = "14a1737c5a43cdff29c09a606c162316"


def main() -> None:
    config = load_config()
    account_id = config["account_id"]

    current = api_request(
        "GET", f"/accounts/{account_id}/cfd_tunnel/{TUNNEL_ID}/configurations"
    )
    ingress = list(current.get("config", {}).get("ingress") or [])

    # Drop catch-all while rebuilding; keep existing host rules
    host_rules = [r for r in ingress if r.get("hostname")]
    host_rules = [r for r in host_rules if r.get("hostname") != HOSTNAME]
    host_rules.append({"hostname": HOSTNAME, "service": SERVICE})
    new_ingress = host_rules + [{"service": "http_status:404"}]

    payload = {"config": {"ingress": new_ingress}}
    result = api_request(
        "PUT",
        f"/accounts/{account_id}/cfd_tunnel/{TUNNEL_ID}/configurations",
        json=payload,
    )
    print("Tunnel ingress updated:")
    print(json.dumps(result.get("config", result), indent=2))

    # DNS CNAME if missing
    records = api_request(
        "GET",
        f"/zones/{ZONE_HYAS_SPACE}/dns_records",
        params={"name": HOSTNAME, "type": "CNAME"},
    )
    if records:
        print(f"DNS already exists: {HOSTNAME} -> {records[0].get('content')}")
    else:
        created = api_request(
            "POST",
            f"/zones/{ZONE_HYAS_SPACE}/dns_records",
            json={
                "type": "CNAME",
                "name": HOSTNAME,
                "content": f"{TUNNEL_ID}.cfargotunnel.com",
                "proxied": True,
            },
        )
        print(f"Created DNS: {HOSTNAME} -> {created.get('content')} id={created.get('id')}")


if __name__ == "__main__":
    main()
