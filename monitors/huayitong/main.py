#!/usr/bin/env python3
"""Huayitong (华医通) West China Hospital appointment monitor — CLI entry."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Project root on sys.path so `config` / `src` imports work when run as a script
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import settings  # noqa: E402
from src.monitor import AppointmentMonitor  # noqa: E402
from src.notifiers import (  # noqa: E402
    ServerChanNotifier,
    TelegramNotifier,
    WeComNotifier,
    build_notifiers,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor Huayitong doctor appointment slots and notify on openings.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single poll then exit",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test all enabled notifiers then exit",
    )
    parser.add_argument(
        "--test-telegram",
        action="store_true",
        help="Test Telegram only",
    )
    parser.add_argument(
        "--test-serverchan",
        action="store_true",
        help="Test ServerChan only",
    )
    parser.add_argument(
        "--test-wecom",
        action="store_true",
        help="Test WeCom group webhook only",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args(argv)

    if args.test_telegram:
        ok = TelegramNotifier().test_connection()
        return 0 if ok else 1

    if args.test_serverchan:
        ok = ServerChanNotifier().test_connection()
        return 0 if ok else 1

    if args.test_wecom:
        ok = WeComNotifier().test_connection()
        return 0 if ok else 1

    if args.test:
        ok = build_notifiers().test_connection()
        return 0 if ok else 1

    settings.require_api_auth()
    monitor = AppointmentMonitor()

    if args.once:
        monitor.run_once()
        return 0

    monitor.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
