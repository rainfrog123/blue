"""Check whether Python HTTP goes through the system proxy (visit google.com)."""
from __future__ import annotations

import urllib.request

URL = "https://www.google.com"


def main() -> None:
    proxies = urllib.request.getproxies()
    print("urllib.getproxies():", proxies or "(none)")

    print(f"\nGET {URL} (default - uses system proxy if set)")
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "oracle-proxy-check/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"  OK status={resp.status} server={resp.headers.get('Server')}")
    except Exception as e:
        print(f"  FAIL {type(e).__name__}: {e}")

    print("\nGET same URL with ProxyHandler({}) — force direct")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(URL, timeout=15) as resp:
            print(f"  OK status={resp.status} (direct works)")
    except Exception as e:
        print(f"  FAIL {type(e).__name__}: {e}")
        if proxies:
            print("  => Python needs the proxy; direct path is blocked/timeout.")


if __name__ == "__main__":
    main()
