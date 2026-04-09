"""
Main appointment monitoring logic.
"""
import os
import random
import time
from datetime import datetime
from typing import Dict, List, Optional

from config import settings, DOCTORS
from .api_client import HuaxitongAPIClient
from .models import AppointmentEntry, DoctorConfig
from .notifiers import TelegramNotifier


class AppointmentMonitor:
    """Monitor hospital appointments and send notifications when slots become available."""

    def __init__(
        self,
        api_client: Optional[HuaxitongAPIClient] = None,
        notifier: Optional[TelegramNotifier] = None,
        doctors: Optional[List[Dict]] = None,
    ):
        """
        Initialize the monitor.

        Args:
            api_client: API client instance (creates default if not provided)
            notifier: Notifier instance (creates default if not provided)
            doctors: List of doctor configurations (defaults to config/doctors.py)
        """
        self.api_client = api_client or HuaxitongAPIClient()
        self.notifier = notifier or TelegramNotifier()
        self.doctors = [
            DoctorConfig.from_dict(d) for d in (doctors or DOCTORS)
        ]

        # Track previous state for change detection
        self._previous_state: Dict[str, Dict] = {}

    def is_peak_hour(self) -> bool:
        """Check if current time is within peak monitoring windows."""
        now_cst = datetime.now(settings.CST_TZ)
        current_time = now_cst.time()

        for start_str, end_str in settings.PEAK_WINDOWS:
            start = datetime.strptime(start_str, "%H:%M:%S").time()
            end = datetime.strptime(end_str, "%H:%M:%S").time()
            if start <= current_time <= end:
                return True

        return False

    def get_wait_time(self) -> float:
        """Get appropriate wait time based on current time."""
        if self.is_peak_hour():
            return settings.PEAK_HOUR_INTERVAL
        else:
            return random.uniform(
                settings.NORMAL_INTERVAL_MIN,
                settings.NORMAL_INTERVAL_MAX
            )

    def _check_for_changes(
        self,
        entries: List[AppointmentEntry],
        doctor_name: str,
    ) -> List[AppointmentEntry]:
        """
        Check for appointments that became bookable.

        Only notifies when slot becomes truly bookable:
        - status becomes 1 (Available) AND availableCount > 0

        Args:
            entries: Current appointment entries
            doctor_name: Name of the doctor

        Returns:
            List of entries that became bookable
        """
        changes = []

        for entry in entries:
            # Track status changes
            status_key = f"{doctor_name}_{entry.id}_status"
            prev_status = self._previous_state.get(status_key, -1)
            self._previous_state[status_key] = entry.status

            # Track availableCount changes
            avail_key = f"{doctor_name}_{entry.id}_avail"
            prev_avail = self._previous_state.get(avail_key, 0)
            self._previous_state[avail_key] = entry.available_count

            # Only notify if slot is NOW bookable (status=1 AND count>0)
            is_now_bookable = entry.status == 1 and entry.available_count > 0
            was_bookable = prev_status == 1 and prev_avail > 0

            # Skip first check (prev_status == -1) to avoid false positives on startup
            if prev_status >= 0 and is_now_bookable and not was_bookable:
                change_details = []
                if prev_status != entry.status:
                    change_details.append(f"status: {prev_status} → {entry.status}")
                if prev_avail != entry.available_count:
                    change_details.append(f"availableCount: {prev_avail} → {entry.available_count}")
                entry.changes_summary = ", ".join(change_details) or "became bookable"
                changes.append(entry)

        return changes

    def _notify_console(self, changes: List[AppointmentEntry]):
        """Print notification to console."""
        now_str = datetime.now(settings.CST_TZ).strftime('%Y-%m-%d %H:%M:%S CST')

        print(f"\n*** APPOINTMENT SLOTS AVAILABLE! ***")
        print(f"Time: {now_str}")
        print(f"Found {len(changes)} new available slot(s):")

        # Group by doctor
        changes_by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in changes:
            doctor_name = change.doctor_name or "Unknown"
            if doctor_name not in changes_by_doctor:
                changes_by_doctor[doctor_name] = []
            changes_by_doctor[doctor_name].append(change)

        slot_counter = 1
        for doctor_name, doctor_changes in changes_by_doctor.items():
            print(f"\n  Doctor: {doctor_name}")
            for change in doctor_changes:
                print(f"    Slot {slot_counter}:")
                print(f"      Date: {change.schedule_date} {change.time_period} ({change.day_desc})")
                print(f"      Department: {change.dept_name}")
                print(f"      Location: {change.adm_location}")
                print(f"      Hospital Area: {change.hospital_area_name}")
                print(f"      Fee: {change.reg_fee} + {change.service_fee} = {change.total_fee} CNY ({change.reg_title_name})")
                print(f"      Available: {change.available_count} slots")
                print(f"      Changes: {change.changes_summary}")
                slot_counter += 1

        print("=" * 60)

    def _notify_system(self, changes: List[AppointmentEntry]):
        """Send system notification (Windows toast or Linux notify-send)."""
        try:
            doctors_list = ", ".join(set(c.doctor_name for c in changes if c.doctor_name))
            message = f"{len(changes)} new slot(s) found for {doctors_list}"
            
            if os.name == 'nt':  # Windows
                import subprocess
                ps_script = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
                $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
                $xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("Appointment Available")) | Out-Null
                $xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{message}")) | Out-Null
                $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
                [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Huaxitong Monitor").Show($toast)
                '''
                subprocess.run(['powershell', '-Command', ps_script], capture_output=True, stderr=subprocess.DEVNULL)
            else:  # Linux - silently skip if notify-send not available
                import subprocess
                subprocess.run(['notify-send', 'Appointment Available', message], 
                             capture_output=True, stderr=subprocess.DEVNULL)
        except:
            pass

    def check_once(self) -> tuple[List[AppointmentEntry], List[AppointmentEntry]]:
        """
        Perform a single check for all doctors.

        Returns:
            Tuple of (all_entries, changed_entries)
        """
        all_entries = []
        all_changes = []

        for doctor in self.doctors:
            response_data = self.api_client.fetch_doctor_appointments(
                doctor.payload,
                doctor.name
            )

            if response_data:
                entries = self.api_client.extract_appointments(
                    response_data,
                    doctor.name
                )

                if entries:
                    all_entries.extend(entries)

                    # Check for changes
                    changes = self._check_for_changes(entries, doctor.name)
                    all_changes.extend(changes)

        return all_entries, all_changes

    def run(self):
        """Main monitoring loop."""
        doctors_names = ", ".join(d.name for d in self.doctors)

        print("Starting appointment monitor...")
        print(f"Normal: {settings.NORMAL_INTERVAL_MIN}-{settings.NORMAL_INTERVAL_MAX}s intervals | "
              f"Peak: {settings.PEAK_HOUR_INTERVAL}s intervals")
        print(f"Monitoring: {doctors_names}")
        print("Anti-detection: Dynamic timestamps, randomized intervals, rotating User-Agents")
        print("Telegram notifications: Enabled")
        print("Tracking: Only truly BOOKABLE slots (status=1 AND availableCount>0)")
        print("=" * 60)

        iteration = 0
        while True:
            try:
                iteration += 1
                timestamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")

                print(f"[{timestamp}] Check #{iteration}")

                # Perform check
                entries, changes = self.check_once()

                if entries:
                    # Display summary
                    total_avail = sum(e.available_count for e in entries)
                    status_1_count = sum(1 for e in entries if e.is_bookable)
                    print(f"[OK] {total_avail} slots, {status_1_count} bookable (status=1)")

                    # Show slot details
                    for entry in entries:
                        print(f"  - {entry.schedule_date} {entry.time_period} | "
                              f"{entry.hospital_area_name} | {entry.dept_name} | "
                              f"Avail:{entry.available_count} | {entry.total_fee} CNY | {entry.status_label}")
                else:
                    print("[WARN] No appointment data")

                # Notify if changes found
                if changes:
                    self._notify_console(changes)
                    self.notifier.send(changes)
                    self._notify_system(changes)

                # Wait for next check
                wait_time = self.get_wait_time()
                is_peak = self.is_peak_hour()
                peak_status = "[PEAK HOUR]" if is_peak else "[Normal]"
                print(f"[{timestamp}] {peak_status} - Waiting {wait_time:.1f} seconds until next check...")
                time.sleep(wait_time)

            except KeyboardInterrupt:
                stop_time = datetime.now(settings.CST_TZ).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"\n\nMonitor stopped by user at {stop_time}")
                break
            except Exception as e:
                error_time = datetime.now(settings.CST_TZ).strftime('%Y-%m-%d %H:%M:%S CST')
                print(f"[{error_time}] Error: {e}")
                error_wait = random.uniform(settings.ERROR_WAIT_MIN, settings.ERROR_WAIT_MAX)
                print(f"[{error_time}] Waiting {error_wait:.1f} seconds before retry...")
                time.sleep(error_wait)
