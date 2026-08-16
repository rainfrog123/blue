"""Telegram Bot API notifier (async)."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional

import aiohttp

from config import settings
from ..models import RosterSlot

_MD_V2_SPECIAL = r"_*[]()~`>#+-=|{}.!"


class TelegramNotifier:
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

    def _build(self, slots: List[RosterSlot]) -> str:
        by_doctor: Dict[str, List[RosterSlot]] = {}
        for slot in slots:
            by_doctor.setdefault(slot.doctor_name, []).append(slot)

        esc = self._escape
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        lines = [
            "🦷 *华西口腔挂号提醒*",
            "",
            f"🏥 *科室*: {esc(settings.DEPARTMENT_NAME)}",
            f"👨‍⚕️ *医生*: {esc(', '.join(by_doctor))}",
            f"⏰ *时间*: {esc(now_str)}",
            f"📋 *号源*: {len(slots)} 个可预约",
            "",
            "━━━━━━━━━━━━━━━",
        ]
        n = 1
        for doctor_slots in by_doctor.values():
            for slot in doctor_slots:
                lines.extend(
                    [
                        "",
                        f"*\\[{n}\\] {esc(slot.doctor_name)} \\({esc(slot.doctor_title)}\\)*",
                        f"   📅 {esc(slot.date)} {esc(slot.time_interval)} \\({esc(slot.day_of_week)}\\)",
                        f"   🎫 {slot.remaining_number}/{slot.total_number}",
                        f"   💰 ¥{esc(slot.appointment_amount)}",
                    ]
                )
                n += 1
        lines.extend(["", "━━━━━━━━━━━━━━━", "⚡ 请尽快打开华西口腔小程序预约\\!"])
        return "\n".join(lines)

    async def send(self, slots: List[RosterSlot]) -> bool:
        if not slots or not self.bot_token or not self.chat_id:
            return False
        cooling, remaining = self._on_cooldown()
        if cooling:
            print(f"[telegram] cooldown {remaining:.0f}s")
            return False

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": self._build(slots),
                        "parse_mode": "MarkdownV2",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json() if resp.status == 200 else {}
                    if resp.status == 200 and result.get("ok"):
                        self.last_notification_time = time.time()
                        print(
                            f"[telegram] sent message_id="
                            f"{result.get('result', {}).get('message_id')}"
                        )
                        return True
                    print(f"[telegram] failed: {resp.status} {result}")
                    return False
        except Exception as exc:
            print(f"[telegram] failed: {exc}")
            return False

    async def test_connection(self) -> bool:
        now = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S")
        msg = (
            "🧪 *Hxkq Telegram 测试*\n\n"
            f"⏰ {self._escape(now)}\n"
            "✅ 华西口腔监控通知正常\\."
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": msg,
                        "parse_mode": "MarkdownV2",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json() if resp.status == 200 else {}
                    ok = resp.status == 200 and result.get("ok")
                    print(f"[telegram] test {'ok' if ok else 'failed'}: {result}")
                    return bool(ok)
        except Exception as exc:
            print(f"[telegram] test failed: {exc}")
            return False
