"""Build notifiers from settings."""
from __future__ import annotations

from typing import List

from config import settings

from .base import MultiNotifier, Notifier
from .serverchan import ServerChanNotifier
from .telegram import TelegramNotifier
from .wecom import WeComNotifier


def build_notifiers(names: List[str] | None = None) -> MultiNotifier:
    selected = names if names is not None else settings.ENABLED_NOTIFIERS
    built: List[Notifier] = []

    for name in selected:
        if name == "telegram":
            if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
                print("[warn] telegram enabled but credentials missing")
                continue
            built.append(TelegramNotifier())
        elif name == "serverchan":
            if not settings.SERVERCHAN_URL:
                print("[warn] serverchan enabled but SERVERCHAN_URL missing")
                continue
            built.append(ServerChanNotifier())
        elif name in ("wecom", "wecom_webhook"):
            if not settings.WECOM_WEBHOOK_URL:
                print("[warn] wecom enabled but WECOM_WEBHOOK_URL missing")
                continue
            built.append(WeComNotifier())
        else:
            print(f"[warn] unknown notifier: {name}")

    return MultiNotifier(built)
