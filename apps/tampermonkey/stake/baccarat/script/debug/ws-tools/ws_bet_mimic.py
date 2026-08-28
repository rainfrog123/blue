#!/usr/bin/env python3
"""
Mimic Pragmatic game websocket bet payloads observed in HAR.

Default mode is LIVE send (to match direct script behavior).
Use --dry-run to preview without sending.

Examples:
  # Preview payloads only
  python baccarat/core/ws_bet_mimic.py \
    --url "wss://gs20.pragmaticplaylive.net/game?...tableId=cbcf6qas8fscb221&type=json" \
    --table cbcf6qas8fscb221 --amount 0.2 --betcode 1

  # Send live frames (default; requires valid session params/cookies)
  python baccarat/core/ws_bet_mimic.py \
    --url "wss://gs20.pragmaticplaylive.net/game?...tableId=cbcf6qas8fscb221&type=json" \
    --table cbcf6qas8fscb221 --amount 0.2 --betcode 1 \
    --cookie "name=value; ..."
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List
from xml.sax.saxutils import escape

try:
    import websockets
except Exception:
    print("Missing dependency: websockets")
    print("Install with: python -m pip install websockets")
    raise


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mimic websocket bet payload(s).")
    p.add_argument(
        "--config",
        default=str(Path(__file__).with_name("config.json")),
        help="Path to JSON config file (default: ./config.json)",
    )
    p.add_argument("--url", help="Full wss:// game websocket URL")
    p.add_argument("--table", help="Table id (e.g. cbcf6qas8fscb221)")
    p.add_argument("--amount", help="Bet amount string/number (e.g. 0.2)")
    p.add_argument("--betcode", help="Bet code (e.g. 1)")
    p.add_argument("--protocol", choices=["xml_lpbet", "json_bet"], help="Payload protocol")
    p.add_argument("--channel", help="XML command channel (e.g. table-cbcf6qas8fscb221)")
    p.add_argument("--game-id", help="Game round id for lpbet (gId)")
    p.add_argument("--user-id", help="User id for lpbet (uId)")
    p.add_argument("--bc", help="lpbet bc value (observed often 0)")
    p.add_argument("--ck", help="Client timestamp/token used in lpbet ck attr")
    p.add_argument("--seq", type=int, help="Base seq for sent payloads")
    p.add_argument("--origin", help="Origin header")
    p.add_argument("--cookie", help="Cookie header value")
    p.add_argument("--user-agent", help="User-Agent header value")
    p.add_argument("--timeout", type=float, default=10.0, help="Connect timeout seconds")
    p.add_argument("--read-seconds", type=float, default=6.0, help="Read window after send")
    p.add_argument("--insecure", action="store_true", help="Disable TLS cert verification")
    p.add_argument("--skip-bets-wrapper", action="store_true", help="Only send 'bet' payload")
    p.add_argument("--dry-run", action="store_true", help="Print payloads only; do not send")
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
    bet = cfg.get("bet", {}) if isinstance(cfg, dict) else {}

    if not args.url and ws.get("url"):
        args.url = ws.get("url")
    if not args.origin:
        args.origin = ws.get("origin") or "https://stake.com"
    if not args.cookie and ws.get("cookie"):
        args.cookie = ws.get("cookie")
    if not args.user_agent and ws.get("user_agent"):
        args.user_agent = ws.get("user_agent")

    if not args.table and bet.get("table"):
        args.table = bet.get("table")
    if args.amount is None and bet.get("amount") is not None:
        args.amount = str(bet.get("amount"))
    if args.betcode is None and bet.get("betcode") is not None:
        args.betcode = str(bet.get("betcode"))
    if args.seq is None:
        args.seq = int(bet.get("seq", 1))
    if not args.protocol:
        args.protocol = str(bet.get("protocol", "xml_lpbet"))
    if not args.channel and bet.get("channel"):
        args.channel = bet.get("channel")
    if not args.game_id and bet.get("game_id"):
        args.game_id = str(bet.get("game_id"))
    if not args.user_id and bet.get("user_id"):
        args.user_id = str(bet.get("user_id"))
    if args.bc is None and bet.get("bc") is not None:
        args.bc = str(bet.get("bc"))
    if args.ck is None and bet.get("ck") is not None:
        args.ck = str(bet.get("ck"))
    if not args.skip_bets_wrapper and bet.get("send_bets_wrapper") is False:
        args.skip_bets_wrapper = True

    if not args.origin:
        args.origin = "https://stake.com"
    return args


def build_headers(args: argparse.Namespace) -> Dict[str, str]:
    h: Dict[str, str] = {"Origin": args.origin}
    if args.cookie:
        h["Cookie"] = args.cookie
    if args.user_agent:
        h["User-Agent"] = args.user_agent
    return h


def build_payloads(args: argparse.Namespace) -> List[str]:
    if args.protocol == "xml_lpbet":
        return build_xml_lpbet_payloads(args)
    return build_json_bet_payloads(args)


def build_json_bet_payloads(args: argparse.Namespace) -> List[str]:
    # Matches frames seen in capture:
    # {"bet":{"bc":"true","amount":"0.2","betcode":"1","table":"...","seq":156}}
    # {"bets":{"bc":"true","table":"...","seq":157,"bet":[{"amount":"0.2","betcode":"1"}]}}
    amount = str(args.amount)
    betcode = str(args.betcode)
    seq0 = int(args.seq)

    out = [
        json.dumps(
            {
                "bet": {
                    "bc": "true",
                    "amount": amount,
                    "betcode": betcode,
                    "table": args.table,
                    "seq": seq0,
                }
            },
            separators=(",", ":"),
        )
    ]

    if not args.skip_bets_wrapper:
        out.append(
            json.dumps(
                {
                    "bets": {
                        "bc": "true",
                        "table": args.table,
                        "seq": seq0 + 1,
                        "bet": [{"amount": amount, "betcode": betcode}],
                    }
                },
                separators=(",", ":"),
            )
        )
    return out


def build_xml_lpbet_payloads(args: argparse.Namespace) -> List[str]:
    amount = escape(str(args.amount))
    channel = escape(str(args.channel or f"table-{args.table}"))
    game_id = escape(str(args.game_id or ""))
    user_id = escape(str(args.user_id or ""))
    bc = escape(str(args.bc if args.bc is not None else "0"))
    ck = escape(str(args.ck if args.ck is not None else str(int(time.time() * 1000))))

    # Observed real frame:
    # <command channel="table-cbcf..."><lpbet gm="mtb_desktop" gId="..." uId="..." ck="..."><bet amt="0.2" bc="0" ck="..."/></lpbet></command>
    payload = (
        f'<command channel="{channel}">'
        f'<lpbet gm="mtb_desktop" gId="{game_id}" uId="{user_id}" ck="{ck}">'
        f'<bet amt="{amount}" bc="{bc}" ck="{ck}"/>'
        f'</lpbet></command>'
    )
    return [payload]


async def run(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    payloads = build_payloads(args)

    print(f"[mode] {'DRY-RUN' if args.dry_run else 'LIVE'}")
    print(f"[url] {args.url}")
    print(f"[table] {args.table}")
    print(f"[protocol] {args.protocol}")
    print(f"[cookie] {'yes' if 'Cookie' in headers else 'no'}")
    for i, p in enumerate(payloads, 1):
        print(f"[payload#{i}] {p}")

    if args.dry_run:
        print("[done] dry-run only. Remove --dry-run to send live.")
        return 0

    ssl_ctx = None
    if args.url.startswith("wss://"):
        ssl_ctx = ssl.create_default_context()
        if args.insecure:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        t0 = time.time()
        async with websockets.connect(
            args.url,
            additional_headers=headers,
            open_timeout=args.timeout,
            ssl=ssl_ctx,
            ping_interval=20,
            ping_timeout=20,
            max_size=4 * 1024 * 1024,
        ) as ws:
            print(f"[ok] connected in {time.time() - t0:.2f}s")

            # Send payloads
            for p in payloads:
                await ws.send(p)
                print(f"[send] {p}")

            # Read responses briefly
            recv = 0
            stop_at = time.time() + args.read_seconds
            while time.time() < stop_at:
                remaining = max(0.05, stop_at - time.time())
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                recv += 1
                preview = msg if isinstance(msg, str) else f"<binary:{len(msg)} bytes>"
                if isinstance(preview, str) and len(preview) > 300:
                    preview = preview[:300] + " ...<truncated>"
                print(f"[recv#{recv}] {preview}")

            print(f"[done] recv_frames={recv}")
            return 0
    except Exception as e:
        print(f"[fail] {type(e).__name__}: {e}")
        print("Tip: Needs valid live URL/session and often fresh cookies.")
        return 2


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    args = apply_config_defaults(args, cfg)
    required = [("url", args.url), ("table", args.table), ("amount", args.amount)]
    if args.protocol == "json_bet":
        required.append(("betcode", args.betcode))
    else:
        required.extend([("channel", args.channel), ("game_id", args.game_id), ("user_id", args.user_id)])
    missing = [name for name, val in required if val in (None, "")]
    if missing:
        print(f"Missing required settings: {', '.join(missing)}")
        print("Provide CLI args or fill config.json.")
        return 1
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())

