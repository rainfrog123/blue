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

from config import ALL_DOCTORS, DOCTORS, settings  # noqa: E402
from src.models import DoctorConfig  # noqa: E402
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
        help="Test WeCom CJC (personal) webhook only",
    )
    parser.add_argument(
        "--doctor",
        metavar="SLUG",
        help="Watch one doctor from config/doctors.json. Default: all active.",
    )
    parser.add_argument(
        "--list-doctors",
        action="store_true",
        help="Print slug / active / hook / doctorId / docCode then exit",
    )
    return parser.parse_args(argv)


def _as_config(item: dict | DoctorConfig) -> DoctorConfig:
    if isinstance(item, DoctorConfig):
        return item
    return DoctorConfig.from_dict(item)


def select_doctors(needle: str | None) -> list[dict | DoctorConfig]:
    if not needle:
        if not DOCTORS:
            raise SystemExit("no active doctors in config/doctors.json")
        return list(DOCTORS)
    n = needle.strip().lower()
    matched: list[dict | DoctorConfig] = []
    known: list[str] = []
    for item in ALL_DOCTORS:
        cfg = _as_config(item)
        known.append(cfg.slug)
        if cfg.slug == n or n in cfg.name.lower():
            matched.append(item)
    if not matched:
        raise SystemExit(f"no doctor matching {needle!r}; known: {', '.join(known)}")
    return matched


def print_doctors() -> None:
    if not ALL_DOCTORS:
        print("no doctors in config/doctors.json")
        return
    for item in ALL_DOCTORS:
        cfg = _as_config(item)
        flag = "on " if cfg.active else "off"
        print(
            f"{cfg.slug:16} {flag}  hook={cfg.wecom_hook}  "
            f"doctorId={cfg.doctor_id}  docCode={cfg.doc_code}"
        )


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args(argv)

    if args.list_doctors:
        print_doctors()
        return 0

    if args.test_telegram:
        ok = TelegramNotifier().test_connection()
        return 0 if ok else 1

    if args.test_serverchan:
        ok = ServerChanNotifier().test_connection()
        return 0 if ok else 1

    if args.test_wecom:
        url = settings.WECOM_TEST_URL
        if not url:
            print("[wecom] CJC hook missing (wecom_cjc / WECOM_TEST_URL)")
            return 1
        ok = WeComNotifier(webhook_url=url, cooldown=0).test_connection()
        return 0 if ok else 1

    if args.test:
        ok = build_notifiers().test_connection()
        return 0 if ok else 1

    settings.require_api_auth()
    doctors = select_doctors(args.doctor)
    slug = None
    if args.doctor:
        slug = _as_config(doctors[0]).slug
    monitor = AppointmentMonitor(doctors=doctors, slug=slug)

    if args.once:
        monitor.run_once()
        return 0

    monitor.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
