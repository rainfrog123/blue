"""
Runtime settings for the Huaxi Stomatology (华西口腔) appointment monitor.

Env / `.env` overrides hardcoded fallbacks. Telegram falls back to
`blue/secrets/cred.json` via `cred_loader` when env is unset.
"""
from __future__ import annotations

import os
import sys
from datetime import timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

_SCRIPTS = None
for _cand in (PROJECT_ROOT, *PROJECT_ROOT.parents):
    _p = _cand / "workstation" / "scripts"
    if (_p / "cred_loader.py").is_file():
        _SCRIPTS = _p
        break
if _SCRIPTS:
    sys.path.insert(0, str(_SCRIPTS))

CST_TZ = timezone(timedelta(hours=8))

API_BASE_URL = os.environ.get(
    "HXKQ_API_BASE",
    "https://uf-wechat.scgh114.com",
)

DEFAULT_HEADERS = {
    "Host": "uf-wechat.scgh114.com",
    "Connection": "keep-alive",
    "token": "",
    "content-type": "application/json",
    "Accept-Encoding": "gzip,compress,br,deflate",
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_7_1 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
        "MicroMessenger/8.0.61(0x18003d2b) NetType/WIFI Language/en"
    ),
    "Referer": "https://servicewechat.com/wx0f0dbe95c1397ee9/164/page-frame.html",
}

# Department — 牙周病科（华西院区）
DEPARTMENT_ID = int(os.environ.get("HXKQ_DEPARTMENT_ID", "7301"))
DEPARTMENT_NAME = os.environ.get("HXKQ_DEPARTMENT_NAME", "牙周病科（华西院区）")

# Lookahead when collecting doctor IDs
DOCTOR_LOOKAHEAD_DAYS = int(os.environ.get("HXKQ_LOOKAHEAD_DAYS", "7"))

# Polling
CHECK_INTERVAL = float(os.environ.get("HXKQ_CHECK_INTERVAL", "20"))
ERROR_WAIT_MIN = float(os.environ.get("HXKQ_ERROR_WAIT_MIN", "10"))
ERROR_WAIT_MAX = float(os.environ.get("HXKQ_ERROR_WAIT_MAX", "20"))
# Refresh doctor roster every N iterations (~1h at 20s)
DOCTOR_REFRESH_EVERY = int(os.environ.get("HXKQ_DOCTOR_REFRESH_EVERY", "180"))

NOTIFICATION_COOLDOWN = int(os.environ.get("HXKQ_NOTIFY_COOLDOWN", "300"))

# Default wecom only; uncomment telegram in .env when needed
ENABLED_NOTIFIERS = [
    n.strip().lower()
    for n in os.environ.get("HXKQ_NOTIFIERS", "wecom").split(",")
    if n.strip()
]

# Hardcoded ServerChan fallback (env overrides)
SERVERCHAN_URL = os.environ.get(
    "SERVERCHAN_URL",
    "https://sctapi.ftqq.com/SCT282278TOxQRSjkfr6zTL0r7gQTi4wyZ.send",
)

# WeCom group webhook (Path B) — no Trusted IP; lands in 企微群
WECOM_WEBHOOK_URL = os.environ.get(
    "WECOM_WEBHOOK_URL",
    "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=685b4dce-8bbc-4d64-9de1-36027e8bc5d1",
)
WECOM_MAX_SLOTS = int(os.environ.get("WECOM_MAX_SLOTS", "3"))


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

LOG_DIR = PROJECT_ROOT / "logs"
SUCCESS_LOG = LOG_DIR / "success.log"
REGULAR_LOG = LOG_DIR / "regular.log"
