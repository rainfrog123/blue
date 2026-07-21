#!/usr/bin/env python3
"""
Smoke-test Decodo Public / management API.

Separate from the proxy gateway client under ../decodo/.
Loads api_key via cred_loader → proxy.decodo.api_key

Usage:
    python test_api.py
    python test_api.py --endpoint traffic
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

BASE_V2 = "https://api.decodo.com/v2"
BASE_STATS = "https://api.decodo.com/api/v2/statistics"


def _ensure_cred_loader() -> None:
    scripts = Path(__file__).resolve().parents[4] / "infra" / "scripts"
    s = str(scripts)
    if s not in sys.path:
        sys.path.insert(0, s)


def load_api_key() -> str:
    _ensure_cred_loader()
    from cred_loader import CRED_PATH, get_proxy_decodo

    key = get_proxy_decodo().get("api_key", "")
    if not key:
        raise SystemExit(f"No proxy.decodo.api_key in {CRED_PATH}")
    print(f"Loaded api_key from {CRED_PATH}")
    return key


def _headers(api_key: str) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": api_key,
    }


def _print_result(label: str, resp: requests.Response) -> None:
    print(f"\n=== {label} ===")
    url = resp.url
    if "api-key=" in url:
        before, _, rest = url.partition("api-key=")
        after = rest.split("&", 1)
        url = before + "api-key=***" + (("&" + after[1]) if len(after) > 1 else "")
    print(f"{resp.request.method} {url}")
    print(f"HTTP {resp.status_code} ({resp.elapsed.total_seconds():.2f}s)")
    ctype = resp.headers.get("content-type", "")
    text = resp.text.strip()
    if "json" in ctype or text.startswith("{") or text.startswith("["):
        try:
            print(json.dumps(resp.json(), indent=2)[:4000])
            return
        except Exception:
            pass
    print(text[:2000] if text else "(empty body)")


def probe_whitelisted_ips(api_key: str) -> requests.Response:
    url = f"{BASE_V2}/whitelisted-ips"
    return requests.get(
        url,
        headers=_headers(api_key),
        params={"api-key": api_key},
        timeout=30,
    )


def probe_endpoints(api_key: str) -> requests.Response:
    return requests.get(
        f"{BASE_V2}/endpoints",
        headers=_headers(api_key),
        params={"api-key": api_key},
        timeout=30,
    )


def probe_traffic(api_key: str, proxy_type: str = "residential_proxies") -> requests.Response:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    payload: dict[str, Any] = {
        "proxyType": proxy_type,
        "startDate": start.strftime("%Y-%m-%d %H:%M:%S"),
        "endDate": end.strftime("%Y-%m-%d %H:%M:%S"),
        "groupBy": "day",
        "limit": 500,
        "page": 1,
        "sortBy": "grouping_key",
        "sortOrder": "asc",
    }
    return requests.post(
        f"{BASE_STATS}/traffic",
        headers=_headers(api_key),
        json=payload,
        timeout=30,
    )


def probe_traffic_residential(api_key: str) -> requests.Response:
    return probe_traffic(api_key, "residential_proxies")


def probe_traffic_mobile(api_key: str) -> requests.Response:
    return probe_traffic(api_key, "mobile_proxies")


def probe_targets_mobile(api_key: str) -> requests.Response:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    payload: dict[str, Any] = {
        "proxyType": "mobile_proxies",
        "startDate": start.strftime("%Y-%m-%d %H:%M:%S"),
        "endDate": end.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return requests.post(
        f"{BASE_STATS}/targets",
        headers=_headers(api_key),
        json=payload,
        timeout=30,
    )


PROBES = {
    "whitelist": ("GET whitelist IPs", probe_whitelisted_ips),
    "endpoints": ("GET endpoints", probe_endpoints),
    "traffic": ("POST traffic residential (last 7d)", probe_traffic_residential),
    "traffic_mobile": ("POST traffic mobile (last 7d)", probe_traffic_mobile),
    "targets_mobile": ("POST targets mobile (last 7d)", probe_targets_mobile),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Test Decodo Public API key")
    parser.add_argument(
        "--endpoint",
        choices=["all", *PROBES.keys()],
        default="all",
        help="Which probe to run (default: all)",
    )
    args = parser.parse_args()

    api_key = load_api_key()
    print(f"api_key length={len(api_key)} prefix={api_key[:8]}…")

    names = list(PROBES.keys()) if args.endpoint == "all" else [args.endpoint]
    ok = 0
    for name in names:
        label, fn = PROBES[name]
        try:
            resp = fn(api_key)
            _print_result(label, resp)
            if 200 <= resp.status_code < 300:
                ok += 1
        except requests.RequestException as exc:
            print(f"\n=== {label} ===\nERROR: {exc}")

    print(f"\nDone: {ok}/{len(names)} probes returned 2xx")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
