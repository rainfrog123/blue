"""
Runtime settings for the Huayitong (华医通) appointment monitor.

Env / `.env` overrides hardcoded fallbacks. Telegram also falls back to
`blue/secrets/cred.json` via `cred_loader` when env is unset.
"""
from __future__ import annotations

import os
import sys
from datetime import timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE from `.env` without requiring python-dotenv."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(PROJECT_ROOT / ".env")


def _add_scripts_path() -> None:
    """Find blue/workstation/scripts so cred_loader can load secrets/cred.json."""
    for cand in (PROJECT_ROOT, *PROJECT_ROOT.parents):
        scripts = cand / "workstation" / "scripts"
        if (scripts / "cred_loader.py").is_file():
            sys.path.insert(0, str(scripts))
            return


_add_scripts_path()

CST_TZ = timezone(timedelta(hours=8))

API_URL = os.environ.get(
    "HUAYITONG_API_URL",
    "https://hytapiv2.cd120.com/cloud/appointment/doctorListModel/selDoctorDetailsTwo",
)

# Empty = direct. This lab PC is WAF-blocked; guest mitmweb is not.
API_PROXY = os.environ.get("HUAYITONG_PROXY", "").strip()
API_PROXY_INSECURE = os.environ.get("HUAYITONG_PROXY_INSECURE", "1").strip() not in {
    "0",
    "false",
    "no",
}

DEFAULT_HEADERS = {
    "Host": "hytapiv2.cd120.com",
    "Mac": "Not Found",
    "Accept": "*/*",
    "Client-Version": "7.1.1",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-GB;q=1",
    "Content-Type": "application/json",
    "Connection": "keep-alive",
}

# Auth — env overrides; defaults from app capture 2026-08-15 (export.txt). JWT exp ~2026-09-14.
API_TOKEN = os.environ.get(
    "HUAYITONG_TOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzg2NzcwMjcyLCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3ODkzNjIyNzJ9.QE39Q08VBr8pUBz7NBe_kd569GFcIqcbF1mDhkD8trI***HXGYAPP",
)
API_ACCESS_TOKEN = os.environ.get(
    "HUAYITONG_ACCESS_TOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzg2NzcwMjcyLCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3ODkzNjIyNzJ9.QE39Q08VBr8pUBz7NBe_kd569GFcIqcbF1mDhkD8trI***HXGYAPP",
)
API_COOKIE = os.environ.get(
    "HUAYITONG_COOKIE",
    "acw_tc=76b20f8b17867738472542366e3e0bd6008ad623664e75c6b17fbaa977b3ba",
)

SERVERCHAN_URL = os.environ.get(
    "SERVERCHAN_URL",
    "https://sctapi.ftqq.com/SCT282278T91zPNpvuek2817He3xtGpSLJ.send",
)

# WeCom group webhook (Path B) — no Trusted IP; lands in 企微群
WECOM_WEBHOOK_URL = os.environ.get(
    "WECOM_WEBHOOK_URL",
    "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=685b4dce-8bbc-4d64-9de1-36027e8bc5d1",
)
WECOM_MAX_SLOTS = int(os.environ.get("WECOM_MAX_SLOTS", "3"))

# Notifier toggles: comma-separated, e.g. "wecom" or "telegram,wecom"
ENABLED_NOTIFIERS = [
    n.strip().lower()
    for n in os.environ.get("HUAYITONG_NOTIFIERS", "wecom,telegram").split(",")
    if n.strip()
]


def _telegram_from_cred() -> tuple[str, str]:
    try:
        from cred_loader import get_telegram

        cred = get_telegram()
        return cred.get("bot_token", ""), cred.get("chat_id", "")
    except Exception:
        return "", ""


_cred_bot, _cred_chat = _telegram_from_cred()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", _cred_bot)
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", _cred_chat)

NOTIFICATION_COOLDOWN = int(os.environ.get("HUAYITONG_NOTIFY_COOLDOWN", "60"))

PEAK_HOUR_INTERVAL = float(os.environ.get("HUAYITONG_PEAK_INTERVAL", "5"))
NORMAL_INTERVAL_MIN = float(os.environ.get("HUAYITONG_INTERVAL_MIN", "15"))
NORMAL_INTERVAL_MAX = float(os.environ.get("HUAYITONG_INTERVAL_MAX", "25"))
ERROR_WAIT_MIN = float(os.environ.get("HUAYITONG_ERROR_WAIT_MIN", "30"))
ERROR_WAIT_MAX = float(os.environ.get("HUAYITONG_ERROR_WAIT_MAX", "60"))

# Release windows when new slots often appear (China Standard Time)
PEAK_WINDOWS = [
    ("07:59:00", "08:04:00"),
    ("19:59:00", "20:04:00"),
]

APP_VERSIONS = ["7.1.1"]
IOS_VERSIONS = [
    "15.7.1",
]
SCALE_VALUES = ["3.00"]


def require_api_auth() -> None:
    """Raise if hospital API credentials are missing."""
    missing = [
        name
        for name, value in (
            ("HUAYITONG_TOKEN", API_TOKEN),
            ("HUAYITONG_ACCESS_TOKEN", API_ACCESS_TOKEN),
            ("HUAYITONG_COOKIE", API_COOKIE),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            "Missing API credentials: "
            + ", ".join(missing)
            + f"\nCopy {PROJECT_ROOT / '.env.example'} → .env and fill tokens from the app."
        )
