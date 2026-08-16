#!/usr/bin/env python3
"""
Quick WebSocket direct-connect probe for Pragmatic/Stake endpoints.

Examples:
  python baccarat/core/ws_direct_check.py --url "wss://dga.pragmaticplaylive.net/ws"
  python baccarat/core/ws_direct_check.py --url "wss://gs20.pragmaticplaylive.net/game?...tableId=cbcf..." --origin "https://stake.com" --cookie "name=value; ..."
  python baccarat/core/ws_direct_check.py --from-har baccarat/core/websocks.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, Optional

try:
    import websockets
except Exception:
    print("Missing dependency: websockets")
    print("Install with: python -m pip install websockets")
    raise


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Probe direct websocket connectivity.")
    p.add_argument(
        "--config",
        default=str(Path(__file__).with_name("config.json")),
        help="Path to JSON config file (default: ./config.json)",
    )
    p.add_argument("--url", help="Full websocket URL (wss://...)")
    p.add_argument("--from-har", help="HAR/JSON file to auto-pick a pragmatic ws URL")
    p.add_argument("--origin", help="Origin header")
    p.add_argument("--cookie", help="Cookie header value")
    p.add_argument("--user-agent", help="User-Agent header value")
    p.add_argument("--timeout", type=float, default=10.0, help="Connect timeout seconds")
    p.add_argument("--read-seconds", type=float, default=8.0, help="How long to read frames")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    p.add_argument(
        "--send",
        action="append",
        default=[],
        help="Optional text frame(s) to send after connect (can be used multiple times)",
    )
    return p.parse_args()


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        print(f"[warn] failed to parse config: {p}")
        return {}


def apply_config_defaults(args: argparse.Namespace, cfg: dict) -> argparse.Namespace:
    ws = cfg.get("ws", {}) if isinstance(cfg, dict) else {}
    if not args.url and ws.get("url"):
        args.url = ws.get("url")
    if not args.origin:
        args.origin = ws.get("origin") or "https://stake.com"
    if not args.cookie and ws.get("cookie"):
        args.cookie = ws.get("cookie")
    if not args.user_agent and ws.get("user_agent"):
        args.user_agent = ws.get("user_agent")
    if not args.origin:
        args.origin = "https://stake.com"
    return args


def pick_url_from_har(path: Path) -> Optional[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    preferred = []
    fallback = []
    for e in entries:
        url = e.get("request", {}).get("url", "")
        if not url.startswith("ws"):
            continue
        if "pragmaticplaylive.net" in url:
            # Prefer game feed first if present
            if "/game" in url:
                preferred.append(url)
            else:
                fallback.append(url)
    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]
    return None


def headers_from_args(args: argparse.Namespace) -> Dict[str, str]:
    h: Dict[str, str] = {"Origin": args.origin}
    if args.cookie:
        h["Cookie"] = args.cookie
    if args.user_agent:
        h["User-Agent"] = args.user_agent
    return h


async def probe(args: argparse.Namespace, url: str) -> int:
    ssl_ctx = None
    if url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context()
        if args.insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    headers = headers_from_args(args)
    print(f"[probe] url={url}")
    print(f"[probe] origin={headers.get('Origin')}")
    print(f"[probe] cookie={'yes' if 'Cookie' in headers else 'no'}")

    t0 = time.time()
    recv = 0
    try:
        async with websockets.connect(
            url,
            additional_headers=headers,
            open_timeout=args.timeout,
            ssl=ssl_ctx,
            ping_interval=20,
            ping_timeout=20,
            max_size=4 * 1024 * 1024,
        ) as ws:
            print(f"[ok] connected in {time.time() - t0:.2f}s")

            for payload in args.send:
                await ws.send(payload)
                print(f"[send] {payload[:180]}")

            read_until = time.time() + args.read_seconds
            while time.time() < read_until:
                remain = max(0.01, read_until - time.time())
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=remain)
                except asyncio.TimeoutError:
                    break
                recv += 1
                msg_preview = msg if isinstance(msg, str) else f"<binary:{len(msg)} bytes>"
                if isinstance(msg_preview, str) and len(msg_preview) > 280:
                    msg_preview = msg_preview[:280] + " ...<truncated>"
                print(f"[recv#{recv}] {msg_preview}")

            print(f"[done] recv_frames={recv}")
            return 0
    except Exception as e:
        print(f"[fail] {type(e).__name__}: {e}")
        print("Hint: direct connect often requires fresh query params, cookies, and valid Origin.")
        return 2


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    args = apply_config_defaults(args, cfg)
    url = args.url
    if not url:
        if not args.from_har:
            print("Provide --url or --from-har (or set ws.url in config.json)")
            return 1
        har_path = Path(args.from_har)
        if not har_path.exists():
            print(f"HAR not found: {har_path}")
            return 1
        url = pick_url_from_har(har_path)
        if not url:
            print("No pragmatic websocket URL found in HAR.")
            return 1
        print(f"[har] selected url: {url}")

    return asyncio.run(probe(args, url))


if __name__ == "__main__":
    sys.exit(main())

