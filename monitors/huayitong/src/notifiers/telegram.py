"""Telegram Bot API notifier."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional

import requests

from config import settings
from ..models import AppointmentEntry

_MD_V2_SPECIAL = r"_*[]()~`>#+-=|{}.!"


class TelegramNotifier:
    """Send MarkdownV2 alerts via Telegram Bot API."""

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> None:
        self.bot_token = bot_token or settings.TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or settings.TELEGRAM_CHAT_ID
        self.cooldown = cooldown if cooldown is not None else settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0.0

    @property
    def api_url(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}"

    def _on_cooldown(self) -> tuple[bool, float]:
        remaining = self.cooldown - (time.time() - self.last_notification_time)
        return remaining > 0, max(0.0, remaining)

    @staticmethod
    def _escape(text: object) -> str:
        s = "" if text is None else str(text)
        for char in _MD_V2_SPECIAL:
            s = s.replace(char, f"\\{char}")
        return s

    def _build_message(self, changes: List[AppointmentEntry]) -> str:
        by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            name = change.doctor_name or "Unknown"
            by_doctor.setdefault(name, []).append(change)

        doctors = ", ".join(by_doctor)
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        esc = self._escape

        lines = [
            "🏥 *华西医院挂号提醒*",
            "",
            f"👨‍⚕️ *医生*: {esc(doctors)}",
            f"⏰ *时间*: {esc(now_str)}",
            f"📋 *号源*: {len(changes)} 个可预约",
            "",
            "━━━━━━━━━━━━━━━",
        ]

        slot = 1
        for doctor_changes in by_doctor.values():
            for change in doctor_changes:
                lines.extend(
                    [
                        "",
                        f"*\\[{slot}\\] {esc(change.schedule_date)} {esc(change.time_period)}*",
                        f"   📅 {esc(change.day_desc)}",
                        f"   🏢 {esc(change.dept_name)}",
                        f"   📍 {esc(change.hospital_area_name)}",
                        f"   🪑 {esc(change.adm_location)}",
                        f"   💰 ¥{esc(change.total_fee)} \\({esc(change.reg_title_name)}\\)",
                        f"   🎫 剩余: {change.available_count}",
                    ]
                )
                slot += 1

        lines.extend(
            [
                "",
                "━━━━━━━━━━━━━━━",
                "⚡ 请尽快打开华西挂号App预约\\!",
            ]
        )
        return "\n".join(lines)

    def send(self, changes: List[AppointmentEntry]) -> bool:
        if not changes:
            return False

        cooling, remaining = self._on_cooldown()
        if cooling:
            print(f"[telegram] cooldown {remaining:.0f}s")
            return False

        try:
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": self._build_message(changes),
                    "parse_mode": "MarkdownV2",
                },
                timeout=10,
            )
            if response.status_code != 200:
                print(f"[telegram] HTTP {response.status_code}: {response.text[:200]}")
                return False

            result = response.json()
            if not result.get("ok"):
                print(f"[telegram] API error: {result.get('description', 'unknown')}")
                return False

            self.last_notification_time = time.time()
            print(f"[telegram] sent message_id={result.get('result', {}).get('message_id')}")
            return True
        except Exception as exc:
            print(f"[telegram] send failed: {exc}")
            return False

    def test_connection(self) -> bool:
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S")
        message = (
            "🧪 *Telegram Bot 测试*\n\n"
            f"⏰ 时间: {self._escape(now_str)}\n"
            "✅ 状态: 连接成功\n\n"
            "━━━━━━━━━━━━━━━\n\n"
            "华西医院挂号监控已配置完成\\!\n"
            "如收到此消息，说明 Telegram 通知正常工作\\."
        )
        try:
            print(f"[telegram] test -> chat_id={self.chat_id}")
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "MarkdownV2",
                },
                timeout=10,
            )
            result = response.json() if response.status_code == 200 else {}
            ok = response.status_code == 200 and result.get("ok")
            print(f"[telegram] test {'ok' if ok else 'failed'}: {response.status_code} {result}")
            return bool(ok)
        except Exception as exc:
            print(f"[telegram] test failed: {exc}")
            return False
