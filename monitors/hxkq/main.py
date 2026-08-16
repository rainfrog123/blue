#!/usr/bin/env python3
"""Huaxi Stomatology (华西口腔) appointment monitor — CLI entry."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.monitor import StomatologyMonitor  # noqa: E402
from src.notifiers import (  # noqa: E402
    ServerChanNotifier,
    TelegramNotifier,
    WeComNotifier,
    build_notifiers,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor Huaxi Stomatology roster slots and notify on openings.",
    )
    p.add_argument("--once", action="store_true", help="Single poll then exit")
    p.add_argument("--test", action="store_true", help="Test enabled notifiers")
    p.add_argument("--test-telegram", action="store_true")
    p.add_argument("--test-serverchan", action="store_true")
    p.add_argument("--test-wecom", action="store_true", help="WeCom group webhook only")
    return p.parse_args(argv)


async def _async_main(args: argparse.Namespace) -> int:
    if args.test_telegram:
        return 0 if await TelegramNotifier().test_connection() else 1
    if args.test_serverchan:
        return 0 if await ServerChanNotifier().test_connection() else 1
    if args.test_wecom:
        return 0 if await WeComNotifier().test_connection() else 1
    if args.test:
        return 0 if await build_notifiers().test_connection() else 1

    monitor = StomatologyMonitor()
    if args.once:
        await monitor.run_once()
        return 0
    await monitor.run()
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_async_main(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
