"""ServerChan (方糖) WeChat push notifier."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional

import requests

from config import settings
from ..models import AppointmentEntry


class ServerChanNotifier:
    """Send Markdown alerts via ServerChan SCT API."""

    def __init__(
        self,
        url: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> None:
        self.url = url or settings.SERVERCHAN_URL
        self.cooldown = cooldown if cooldown is not None else settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0.0

    def _on_cooldown(self) -> tuple[bool, float]:
        remaining = self.cooldown - (time.time() - self.last_notification_time)
        return remaining > 0, max(0.0, remaining)

    def _build(self, changes: List[AppointmentEntry]) -> tuple[str, str, str]:
        by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            name = change.doctor_name or "Unknown"
            by_doctor.setdefault(name, []).append(change)

        doctors = ", ".join(by_doctor)
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        title = f"Found {len(changes)} appointment slots!"[:32]

        lines = [
            "## Appointment Information",
            f"**Doctor**: {doctors}",
            f"**Time**: {now_str}",
            f"**Found**: {len(changes)} available slot(s)",
            "",
            "### Slot Details:",
        ]

        slot = 1
        for doctor_name, doctor_changes in by_doctor.items():
            lines.extend(["", f"### {doctor_name}"])
            for change in doctor_changes:
                lines.extend(
                    [
                        "",
                        f"**Slot {slot}:**",
                        f"- Date: {change.schedule_date} {change.time_period} ({change.day_desc})",
                        f"- Department: {change.dept_name}",
                        f"- Location: {change.adm_location}",
                        f"- Hospital Area: {change.hospital_area_name}",
                        f"- Fee: {change.reg_fee} + {change.service_fee} = {change.total_fee} ({change.reg_title_name})",
                        f"- Available: {change.available_count}",
                        f"- Changes: {change.changes_summary}",
                    ]
                )
                slot += 1

        lines.extend(
            [
                "",
                "---",
                "**Reminder**: Book in the West China / Huayitong app ASAP.",
            ]
        )
        short = f"Found {len(changes)} slots - {changes[0].schedule_date} {changes[0].time_period}"[:64]
        return title, "\n".join(lines), short

    def send(self, changes: List[AppointmentEntry]) -> bool:
        if not changes:
            return False

        cooling, remaining = self._on_cooldown()
        if cooling:
            print(f"[serverchan] cooldown {remaining:.0f}s")
            return False

        try:
            title, desp, short = self._build(changes)
            response = requests.post(
                self.url,
                data={"title": title, "desp": desp, "short": short, "noip": "1"},
                timeout=10,
            )
            if response.status_code != 200:
                print(f"[serverchan] HTTP {response.status_code}: {response.text[:200]}")
                return False

            result = response.json()
            if result.get("code") == 0 or result.get("errno") == 0:
                self.last_notification_time = time.time()
                print(f"[serverchan] sent pushid={result.get('data', {}).get('pushid')}")
                return True

            print(f"[serverchan] error: {result.get('message') or result.get('errmsg')}")
            return False
        except Exception as exc:
            print(f"[serverchan] send failed: {exc}")
            return False

    def test_connection(self) -> bool:
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "title": "ServerChan API Test",
            "desp": (
                f"## API Connection Test\n\n**Time**: {now_str}\n\n"
                "Huayitong monitor ServerChan path OK."
            ),
            "short": "API test message",
            "noip": "1",
        }
        try:
            print(f"[serverchan] test → {self.url}")
            response = requests.post(self.url, data=data, timeout=10)
            result = response.json() if response.status_code == 200 else {}
            ok = response.status_code == 200 and (
                result.get("code") == 0 or result.get("errno") == 0
            )
            print(f"[serverchan] test {'ok' if ok else 'failed'}: {result}")
            return bool(ok)
        except Exception as exc:
            print(f"[serverchan] test failed: {exc}")
            return False
