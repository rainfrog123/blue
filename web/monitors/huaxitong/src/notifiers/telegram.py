"""
Telegram notification service.
"""
import time
from datetime import datetime
from typing import List, Dict

import requests

from config import settings
from ..models import AppointmentEntry


class TelegramNotifier:
    """Send notifications via Telegram Bot API."""

    def __init__(
        self,
        bot_token: str = None,
        chat_id: str = None,
        cooldown: int = None,
    ):
        """
        Initialize the notifier.

        Args:
            bot_token: Telegram bot token (defaults to settings)
            chat_id: Telegram chat ID (defaults to settings)
            cooldown: Cooldown period in seconds between notifications
        """
        self.bot_token = bot_token or settings.TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or settings.TELEGRAM_CHAT_ID
        self.cooldown = cooldown or settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0

    @property
    def api_url(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}"

    def _is_on_cooldown(self) -> tuple[bool, float]:
        """Check if notification is on cooldown."""
        current_time = time.time()
        time_since_last = current_time - self.last_notification_time
        remaining = self.cooldown - time_since_last
        return remaining > 0, max(0, remaining)

    def _build_notification_content(
        self,
        changes: List[AppointmentEntry],
    ) -> str:
        """Build notification message in Telegram MarkdownV2 format."""
        changes_by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            doctor_name = change.doctor_name or "Unknown"
            if doctor_name not in changes_by_doctor:
                changes_by_doctor[doctor_name] = []
            changes_by_doctor[doctor_name].append(change)

        doctors_list = ", ".join(changes_by_doctor.keys())
        now_str = datetime.now(settings.CST_TZ).strftime('%Y-%m-%d %H:%M:%S CST')

        lines = [
            f"🏥 *华西医院挂号提醒*",
            "",
            f"👨‍⚕️ *医生*: {self._escape(doctors_list)}",
            f"⏰ *时间*: {self._escape(now_str)}",
            f"📋 *号源*: {len(changes)} 个可预约",
            "",
            "━━━━━━━━━━━━━━━",
        ]

        slot_counter = 1
        for doctor_name, doctor_changes in changes_by_doctor.items():
            for change in doctor_changes:
                lines.extend([
                    "",
                    f"*\\[{slot_counter}\\] {self._escape(change.schedule_date)} {self._escape(change.time_period)}*",
                    f"   📅 {self._escape(change.day_desc)}",
                    f"   🏢 {self._escape(change.dept_name)}",
                    f"   📍 {self._escape(change.hospital_area_name)}",
                    f"   🪑 {self._escape(change.adm_location)}",
                    f"   💰 ¥{self._escape(str(change.total_fee))} \\({self._escape(change.reg_title_name)}\\)",
                    f"   🎫 剩余: {change.available_count}",
                ])
                slot_counter += 1

        lines.extend([
            "",
            "━━━━━━━━━━━━━━━",
            "⚡ 请尽快打开华西挂号App预约\\!",
        ])

        return "\n".join(lines)

    def _escape(self, text: str) -> str:
        """Escape special characters for Telegram MarkdownV2."""
        if text is None:
            return ""
        special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        for char in special_chars:
            text = str(text).replace(char, f'\\{char}')
        return text

    def send(self, changes: List[AppointmentEntry]) -> bool:
        """Send notification about available appointments."""
        if not changes:
            return False

        on_cooldown, remaining = self._is_on_cooldown()
        if on_cooldown:
            print(f"Notification cooldown: {remaining:.0f}s remaining (preventing spam)")
            return False

        try:
            message = self._build_notification_content(changes)

            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "MarkdownV2",
            }

            print(f"Sending Telegram notification...")
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    message_id = result.get("result", {}).get("message_id", "N/A")
                    print(f"Telegram notification sent! Message ID: {message_id}")
                    self.last_notification_time = time.time()
                    return True
                else:
                    print(f"Telegram API error: {result.get('description', 'Unknown error')}")
            else:
                print(f"HTTP error: {response.status_code}")
                print(f"   Response: {response.text[:200]}")

        except Exception as e:
            print(f"Failed to send Telegram notification: {e}")

        return False

    def test_connection(self) -> bool:
        """Test the Telegram bot connection with a test message."""
        try:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            message = f"""🧪 *Telegram Bot 测试*

⏰ 时间: {self._escape(now_str)}
✅ 状态: 连接成功

━━━━━━━━━━━━━━━

华西医院挂号监控已配置完成\\!
如收到此消息，说明 Telegram 通知正常工作\\."""

            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "MarkdownV2",
            }

            print(f"Testing Telegram Bot API...")
            print(f"   Chat ID: {self.chat_id}")
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json=payload,
                timeout=10
            )

            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"   Response: {result}")
                if result.get("ok"):
                    message_id = result.get("result", {}).get("message_id", "N/A")
                    print(f"Test notification sent! Message ID: {message_id}")
                    return True
                else:
                    print(f"Telegram API error: {result.get('description', 'Unknown')}")
            else:
                print(f"HTTP error: {response.status_code}")
                print(f"   Response: {response.text[:200]}")

        except Exception as e:
            print(f"Test failed: {e}")

        return False
