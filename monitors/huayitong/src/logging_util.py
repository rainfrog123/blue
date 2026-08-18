"""Append-only hit log so a missed WeCom/Telegram push still leaves a record."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List

from config import settings
from .models import AppointmentEntry


def cst_stamp() -> str:
    return datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")


def log_hit(changes: List[AppointmentEntry], path: Path | None = None) -> None:
    """Write found slots to disk (fsync) before / regardless of push."""
    if not changes:
        return
    dest = path or settings.HIT_LOG
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"[{cst_stamp()}] HIT {len(changes)} slot(s)"]
    for c in changes:
        lines.append(
            f"  {c.doctor_name}  {c.schedule_date} {c.time_period}  {c.dept_name}  "
            f"status={c.status} avail={c.available_count} remain={c.remaining_num} "
            f"¥{c.total_fee:g}  {c.changes_summary}  id={c.id}  {c.adm_location}"
        )
    blob = "\n".join(lines) + "\n"
    with dest.open("a", encoding="utf-8") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    print(f"[hit] logged {dest}")
