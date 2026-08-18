"""Polling loop: fetch slots → detect newly bookable → notify."""
from __future__ import annotations

import os
import random
import subprocess
import time
from collections import deque
from datetime import datetime
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from config import DOCTORS, settings
from .api_client import HuayitongAPIClient
from .logging_util import log_hit
from .models import AppointmentEntry, DoctorConfig
from .notifiers import MultiNotifier, WeComNotifier, build_notifiers
from .state import SlotStateTracker


class AppointmentMonitor:
    """Monitor Huayitong doctor schedules and alert on slot edges."""

    def __init__(
        self,
        api_client: Optional[HuayitongAPIClient] = None,
        notifier: Optional[MultiNotifier] = None,
        doctors: Optional[Sequence[dict | DoctorConfig]] = None,
        slug: Optional[str] = None,
    ) -> None:
        self.api_client = api_client or HuayitongAPIClient()
        self.notifier = notifier or build_notifiers()
        self.doctors = self._normalize_doctors(doctors or DOCTORS)
        if slug:
            self.slug = slug
        elif len(self.doctors) == 1:
            self.slug = self.doctors[0].slug
        else:
            self.slug = None
        self.hit_log = settings.hit_log_path(self.slug)
        self.state = SlotStateTracker(path=settings.state_path(self.slug))
        self._tail: Deque[str] = deque(maxlen=int(settings.TAIL_LINES))
        self._hook_by_name = {d.name: d.wecom_hook for d in self.doctors}
        self._hit_log_mtime = self._hits_log_mtime()
        self._last_ok = True

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
            entries = self.api_client.extract_appointments(raw, doctor.name)
            all_entries.extend(entries)
            all_changes.extend(self.state.newly_bookable(entries, doctor.name))

        if all_entries:
            self.state.mark_warm()
        return all_entries, all_changes

    def _print_changes(self, changes: List[AppointmentEntry]) -> None:
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        print("\n*** APPOINTMENT SLOTS AVAILABLE! ***")
        print(f"Time: {now_str}")
        print(f"Found {len(changes)} slot change(s):")

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
        """Single poll (useful for cron / debug). Returns changed slots."""
        entries, changes = self.check_once()
        self._log_summary(entries)
        if changes:
            print(f"NEW {len(changes)}")
            self._print_changes(changes)
            try:
                log_hit(changes, path=self.hit_log)
            except Exception as exc:
                print(f"[hit log error] {exc}")
            self._dispatch(changes)
            self._system_toast(changes)
        elif not entries:
            print("no slots")
        return changes

    def _log_summary(self, entries: List[AppointmentEntry]) -> None:
        lines = []
        if not entries:
            print("[warn] No appointment data")
            lines.append("no slots")
        else:
            for entry in entries:
                line = (
                    f"  {entry.schedule_date} {entry.dept_name} "
                    f"status={entry.status} avail={entry.available_count} "
                    f"remain={entry.remaining_num} ¥{entry.total_fee:g}"
                )
                print(line)
                lines.append(line)
        self._tail.append("\n".join(lines))
        print()

    def _hook_for(self, change: AppointmentEntry) -> str:
        return self._hook_by_name.get(change.doctor_name or "", "gq")

    def _dispatch(self, changes: List[AppointmentEntry]) -> None:
        gq = [c for c in changes if self._hook_for(c) != "cjc"]
        cjc = [c for c in changes if self._hook_for(c) == "cjc"]
        if gq:
            self.notifier.send(gq)
        if cjc:
            url = settings.WECOM_TEST_URL
            if not url:
                print("[wecom] CJC hook missing")
            else:
                WeComNotifier(webhook_url=url, cooldown=0).send(cjc)

    def _hits_log_mtime(self) -> float:
        try:
            return self.hit_log.stat().st_mtime
        except OSError:
            return 0.0

    def _heartbeat_text(self) -> str:
        stamp = datetime.now(settings.CST_TZ).strftime("%H:%M")
        names = " ".join((d.name.split()[0] if d.name else "?") for d in self.doctors)
        log_name = self.hit_log.name
        mtime = self._hits_log_mtime()
        if mtime > self._hit_log_mtime:
            hits = f"{log_name} updated"
        elif mtime == 0:
            hits = f"{log_name} none"
        else:
            hits = f"{log_name} unchanged"
        self._hit_log_mtime = mtime
        status = "ok" if self._last_ok else "err"
        return f"华医通 {stamp} {status} {names} · {hits}"

    def _send_heartbeat(self) -> None:
        text = self._heartbeat_text()
        print(f"[heartbeat] {text}")
        url = settings.WECOM_TEST_URL
        if not url:
            print("[wecom] CJC hook missing (heartbeat)")
            return
        WeComNotifier(webhook_url=url, cooldown=0).send_text(text)

    def run(self) -> None:
        names = ", ".join(d.name for d in self.doctors)
        print("huayitong poller", names)
        print(
            "doctors",
            ", ".join(
                f"{d.slug} hook={d.wecom_hook} doctorId={d.doctor_id} "
                f"docCode={d.doc_code} active={d.active}"
                for d in self.doctors
            ),
        )
        print(
            f"normal {settings.NORMAL_INTERVAL_MIN:g}-{settings.NORMAL_INTERVAL_MAX:g}s | "
            f"peak {settings.PEAK_HOUR_INTERVAL:g}s"
        )
        print(
            f"notifiers: {settings.ENABLED_NOTIFIERS}  "
            f"heartbeat CJC  slots by hook  "
            f"fail backoff {settings.ERROR_WAIT_MIN:g}-{settings.ERROR_WAIT_MAX:g}s  "
            f"tail {settings.WECOM_TAIL_SEC:g}s"
        )
        print("Alert rule: status/avail/remain edge, or new id after warmup if status==1 or seats>0")
        print(f"hit log {self.hit_log}")
        print(f"state {self.state.path}")
        print("=" * 60)

        last_tail = time.monotonic()
        while True:
            failed = False
            try:
                self.run_once()
                self._last_ok = True
            except KeyboardInterrupt:
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                print(f"\nStopped by user at {stamp}")
                break
            except Exception as exc:
                failed = True
                self._last_ok = False
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                err_line = f"{stamp} err {type(exc).__name__} {exc}"
                print(err_line)
                self._tail.append(err_line)
            if last_tail and time.monotonic() - last_tail >= settings.WECOM_TAIL_SEC:
                last_tail = time.monotonic()
                self._send_heartbeat()
            if failed:
                wait = random.uniform(settings.ERROR_WAIT_MIN, settings.ERROR_WAIT_MAX)
                print(f"stop {wait:.1f}s then retry")
                time.sleep(wait)
                continue
            time.sleep(self.wait_seconds())
