"""Append-only session logs under logs/."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List

from config import settings
from .models import RosterSlot


def ensure_log_dir() -> None:
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)


def _stamp() -> str:
    return datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")


def append(path: Path, line: str) -> None:
    ensure_log_dir()
    with path.open("a", encoding="utf-8") as f:
        f.write(line if line.endswith("\n") else line + "\n")


def session_start() -> None:
    ensure_log_dir()
    marker = f"\n{'=' * 60}\n[{_stamp()}] New monitoring session started\n{'=' * 60}\n"
    for path in (settings.SUCCESS_LOG, settings.REGULAR_LOG):
        with path.open("a", encoding="utf-8") as f:
            f.write(marker)


def session_end() -> None:
    line = f"[{_stamp()}] Monitoring session ended\n{'=' * 60}\n\n"
    for path in (settings.SUCCESS_LOG, settings.REGULAR_LOG):
        append(path, line)


def log_success(slots: List[RosterSlot]) -> None:
    lines = [f"[{_stamp()}] Found {len(slots)} newly bookable slot(s):"]
    for slot in slots:
        lines.append(
            f"  - Dr. {slot.doctor_name} ({slot.doctor_title}): "
            f"{slot.date} {slot.day_of_week} {slot.time_interval} - "
            f"{slot.remaining_number}/{slot.total_number} - ¥{slot.appointment_amount}"
            + (f" ({slot.changes_summary})" if slot.changes_summary else "")
        )
    append(settings.SUCCESS_LOG, "\n".join(lines) + "\n")


def log_regular(doctor_count: int, bookable_count: int) -> None:
    append(
        settings.REGULAR_LOG,
        f"[{_stamp()}] Checked {doctor_count} doctors, "
        f"{bookable_count} currently bookable slots",
    )
