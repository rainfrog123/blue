"""
ServerChan WeChat notification service.
"""
import time
from datetime import datetime
from typing import List, Dict, Any

import requests

from config import settings
from ..models import AppointmentEntry


class ServerChanNotifier:
    """Send notifications via ServerChan WeChat service."""

    def __init__(
        self,
        url: str = None,
        cooldown: int = None,
    ):
        """
        Initialize the notifier.

        Args:
            url: ServerChan API URL (defaults to settings)
            cooldown: Cooldown period in seconds between notifications
        """
        self.url = url or settings.SERVERCHAN_URL
        self.cooldown = cooldown or settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0

    def _is_on_cooldown(self) -> tuple[bool, float]:
        """
        Check if notification is on cooldown.

        Returns:
            Tuple of (is_on_cooldown, remaining_seconds)
        """
        current_time = time.time()
        time_since_last = current_time - self.last_notification_time
        remaining = self.cooldown - time_since_last

        return remaining > 0, max(0, remaining)

    def _build_notification_content(
        self,
        changes: List[AppointmentEntry],
    ) -> tuple[str, str, str]:
        """
        Build notification title and content.

        Args:
            changes: List of changed appointment entries

        Returns:
            Tuple of (title, description, short_message)
        """
        # Title max 32 chars per ServerChan API spec
        title = f"Found {len(changes)} appointment slots!"[:32]

        # Group changes by doctor
        changes_by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            doctor_name = change.doctor_name or "Unknown"
            if doctor_name not in changes_by_doctor:
                changes_by_doctor[doctor_name] = []
            changes_by_doctor[doctor_name].append(change)

        doctors_list = ", ".join(changes_by_doctor.keys())
        now_str = datetime.now(settings.CST_TZ).strftime('%Y-%m-%d %H:%M:%S CST')

        # Build detailed message content in Markdown
        desp_lines = [
            "## Appointment Information",
            f"**Doctor**: {doctors_list}",
            f"**Time**: {now_str}",
            f"**Found**: {len(changes)} available slot(s)",
            "",
            "### Slot Details:"
        ]

        slot_counter = 1
        for doctor_name, doctor_changes in changes_by_doctor.items():
            desp_lines.extend([
                "",
                f"### {doctor_name}"
            ])

            for change in doctor_changes:
                fee_info = (
                    f"Reg: {change.reg_fee} + Service: {change.service_fee} "
                    f"= Total: {change.total_fee} ({change.reg_title_name})"
                )

                desp_lines.extend([
                    "",
                    f"**Slot {slot_counter}:**",
                    f"- Date: {change.schedule_date} {change.time_period} ({change.day_desc})",
                    f"- Department: {change.dept_name}",
                    f"- Location: {change.adm_location}",
                    f"- Hospital Area: {change.hospital_area_name}",
                    f"- Fee: {fee_info}",
                    f"- Available: {change.available_count}",
                    f"- Changes: {change.changes_summary}"
                ])
                slot_counter += 1

        desp_lines.extend([
            "",
            "---",
            "**Reminder**: Please book via the West China Hospital App ASAP!"
        ])

        desp = "\n".join(desp_lines)
        # Short max 64 chars per ServerChan API spec
        short = f"Found {len(changes)} slots - {changes[0].schedule_date} {changes[0].time_period}"[:64]

        return title, desp, short

    def send(self, changes: List[AppointmentEntry]) -> bool:
        """
        Send notification about available appointments.

        Args:
            changes: List of changed appointment entries

        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not changes:
            return False

        # Check cooldown
        on_cooldown, remaining = self._is_on_cooldown()
        if on_cooldown:
            print(f"Notification cooldown: {remaining:.0f}s remaining (preventing spam)")
            return False

        try:
            title, desp, short = self._build_notification_content(changes)

            notification_data = {
                "title": title,
                "desp": desp,
                "short": short,
                "noip": "1"  # Hide IP for privacy
            }

            print(f"Sending WeChat notification via ServerChan...")
            print(f"   URL: {self.url}")
            print(f"   Title: {notification_data['title']}")

            response = requests.post(self.url, data=notification_data, timeout=10)

            if response.status_code == 200:
                result = response.json()
                print(f"   Response: {result}")
                if result.get("code") == 0 or result.get("errno") == 0:
                    pushid = result.get("data", {}).get("pushid", "N/A")
                    print(f"WeChat notification sent successfully! PushID: {pushid}")
                    self.last_notification_time = time.time()
                    return True
                else:
                    errmsg = result.get("message") or result.get("errmsg") or "Unknown error"
                    print(f"ServerChan error: {errmsg}")
            else:
                print(f"HTTP error: {response.status_code}")
                print(f"   Response: {response.text[:200]}")

        except Exception as e:
            print(f"Failed to send WeChat notification: {e}")

        return False

    def test_connection(self) -> bool:
        """
        Test the ServerChan connection with a test message.

        Returns:
            True if test was successful
        """
        try:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            data = {
                "title": "ServerChan API Test",  # Max 32 chars
                "desp": f"""## API Connection Test

**Time**: {now_str}

**Status**: Testing ServerChan API connection

### Test Details:

- API endpoint: OK
- WeChat push service: Connecting
- Appointment monitor: Ready

---

If you receive this message, ServerChan is configured correctly!""",
                "short": "API test message",
                "noip": "1"
            }

            print(f"Testing ServerChan API...")
            print(f"   URL: {self.url}")
            response = requests.post(self.url, data=data, timeout=10)

            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"   Response: {result}")
                if result.get("code") == 0 or result.get("errno") == 0:
                    pushid = result.get("data", {}).get("pushid", "N/A")
                    print(f"Test notification sent! PushID: {pushid}")
                    return True
                else:
                    errmsg = result.get("message") or result.get("errmsg") or "Unknown"
                    print(f"ServerChan error: {errmsg}")
            else:
                print(f"HTTP error: {response.status_code}")
                print(f"   Response: {response.text[:200]}")

        except Exception as e:
            print(f"Test failed: {e}")

        return False
