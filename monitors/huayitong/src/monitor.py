"""Polling loop: fetch slots → detect newly bookable → notify."""
from __future__ import annotations

import os
import random
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from config import DOCTORS, settings
from .api_client import HuayitongAPIClient
from .models import AppointmentEntry, DoctorConfig
from .notifiers import MultiNotifier, build_notifiers
from .state import SlotStateTracker


class AppointmentMonitor:
    """Monitor Huayitong doctor schedules and alert on newly bookable slots."""

    def __init__(
        self,
        api_client: Optional[HuayitongAPIClient] = None,
        notifier: Optional[MultiNotifier] = None,
        doctors: Optional[Sequence[dict | DoctorConfig]] = None,
    ) -> None:
        self.api_client = api_client or HuayitongAPIClient()
        self.notifier = notifier or build_notifiers()
        self.doctors = self._normalize_doctors(doctors or DOCTORS)
        self.state = SlotStateTracker()

    @staticmethod
    def _normalize_doctors(
        doctors: Sequence[dict | DoctorConfig],
    ) -> List[DoctorConfig]:
        out: List[DoctorConfig] = []
        for item in doctors:
            if isinstance(item, DoctorConfig):
                out.append(item)
            else:
                out.append(DoctorConfig.from_dict(item))
        return out

    def is_peak_hour(self) -> bool:
        current = datetime.now(settings.CST_TZ).time()
        for start_str, end_str in settings.PEAK_WINDOWS:
            start = datetime.strptime(start_str, "%H:%M:%S").time()
            end = datetime.strptime(end_str, "%H:%M:%S").time()
            if start <= current <= end:
                return True
        return False

    def wait_seconds(self) -> float:
        if self.is_peak_hour():
            return settings.PEAK_HOUR_INTERVAL
        return random.uniform(settings.NORMAL_INTERVAL_MIN, settings.NORMAL_INTERVAL_MAX)

    def check_once(self) -> Tuple[List[AppointmentEntry], List[AppointmentEntry]]:
        all_entries: List[AppointmentEntry] = []
        all_changes: List[AppointmentEntry] = []

        for doctor in self.doctors:
            raw = self.api_client.fetch_doctor_appointments(doctor.payload, doctor.name)
            if not raw:
                continue
            entries = self.api_client.extract_appointments(raw, doctor.name)
            if not entries:
                continue
            all_entries.extend(entries)
            all_changes.extend(self.state.newly_bookable(entries, doctor.name))

        if all_entries:
            self.state.mark_warm()
        return all_entries, all_changes

    def _print_changes(self, changes: List[AppointmentEntry]) -> None:
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        print("\n*** APPOINTMENT SLOTS AVAILABLE! ***")
        print(f"Time: {now_str}")
        print(f"Found {len(changes)} newly bookable slot(s):")

        by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            by_doctor.setdefault(change.doctor_name or "Unknown", []).append(change)

        slot = 1
        for doctor_name, doctor_changes in by_doctor.items():
            print(f"\n  Doctor: {doctor_name}")
            for change in doctor_changes:
                print(f"    Slot {slot}:")
                print(
                    f"      Date: {change.schedule_date} {change.time_period} "
                    f"({change.day_desc})"
                )
                print(f"      Department: {change.dept_name}")
                print(f"      Location: {change.adm_location}")
                print(f"      Area: {change.hospital_area_name}")
                print(
                    f"      Fee: {change.reg_fee} + {change.service_fee} = "
                    f"{change.total_fee} CNY ({change.reg_title_name})"
                )
                print(f"      Available: {change.available_count}")
                print(f"      Changes: {change.changes_summary}")
                slot += 1
        print("=" * 60)

    def _system_toast(self, changes: List[AppointmentEntry]) -> None:
        doctors = ", ".join(sorted({c.doctor_name for c in changes if c.doctor_name}))
        message = f"{len(changes)} new slot(s) for {doctors}"
        try:
            if os.name == "nt":
                # Keep message simple for PowerShell string safety
                safe = message.replace('"', "'")
                ps = f"""
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
                $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
                $xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("Huayitong")) | Out-Null
                $xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{safe}")) | Out-Null
                $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
                [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Huayitong Monitor").Show($toast)
                """
                subprocess.run(
                    ["powershell", "-Command", ps],
                    capture_output=True,
                    check=False,
                )
            else:
                subprocess.run(
                    ["notify-send", "Huayitong", message],
                    capture_output=True,
                    check=False,
                )
        except Exception:
            pass

    def run_once(self) -> List[AppointmentEntry]:
        """Single poll (useful for cron / debug). Returns newly bookable slots."""
        entries, changes = self.check_once()
        self._log_summary(entries)
        if changes:
            self._print_changes(changes)
            self.notifier.send(changes)
            self._system_toast(changes)
        return changes

    def _log_summary(self, entries: List[AppointmentEntry]) -> None:
        if not entries:
            print("[warn] No appointment data")
            return
        total_avail = sum(e.available_count for e in entries)
        bookable = sum(1 for e in entries if e.is_bookable)
        print(f"[ok] {total_avail} remaining seats, {bookable} bookable slots")
        for entry in entries:
            print(
                f"  - {entry.schedule_date} {entry.time_period} | "
                f"{entry.hospital_area_name} | {entry.dept_name} | "
                f"Avail:{entry.available_count} | {entry.total_fee} CNY | "
                f"{entry.status_label}"
            )

    def run(self) -> None:
        names = ", ".join(d.name for d in self.doctors)
        print("Starting Huayitong appointment monitor...")
        print(
            f"Interval normal {settings.NORMAL_INTERVAL_MIN}-{settings.NORMAL_INTERVAL_MAX}s | "
            f"peak {settings.PEAK_HOUR_INTERVAL}s"
        )
        print(f"Monitoring: {names}")
        print(f"Notifiers: {settings.ENABLED_NOTIFIERS}")
        print("Alert rule: newly bookable only (status=1 AND availableCount>0)")
        print("=" * 60)

        iteration = 0
        while True:
            try:
                iteration += 1
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                print(f"[{stamp}] Check #{iteration}")

                self.run_once()

                wait = self.wait_seconds()
                peak = "[PEAK]" if self.is_peak_hour() else "[normal]"
                print(f"[{stamp}] {peak} sleep {wait:.1f}s")
                time.sleep(wait)
            except KeyboardInterrupt:
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                print(f"\nStopped by user at {stamp}")
                break
            except Exception as exc:
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                wait = random.uniform(settings.ERROR_WAIT_MIN, settings.ERROR_WAIT_MAX)
                print(f"[{stamp}] Error: {exc}")
                print(f"[{stamp}] Retry in {wait:.1f}s")
                time.sleep(wait)
