"""Append-only hit log so a missed WeCom/Telegram push still leaves a record."""
from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from config import settings
from .models import AppointmentEntry

_HIT_START = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) CST\] HIT ",
    re.M,
)
_RECORD_SPLIT = re.compile(r"(?=^\[\d{4}-\d{2}-\d{2} )", re.M)


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
        lines.extend(
            [
                f"  {c.doctor_name}",
                f"  {c.schedule_date} {c.time_period}",
                f"  {c.dept_name}",
                f"  status={c.status}  avail={c.available_count}  remain={c.remaining_num}  ¥{c.total_fee:g}",
                f"  {c.changes_summary}",
                f"  id={c.id}",
                f"  {c.adm_location}",
            ]
        )
    blob = "\n".join(lines) + "\n\n"
    with dest.open("a", encoding="utf-8") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    print(f"[hit] logged {dest}")


def iter_hit_records(path: Path) -> List[Tuple[datetime, str]]:
    """Split hits-*.log into (CST timestamp, full record) pairs."""
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    out: List[Tuple[datetime, str]] = []
    for part in _RECORD_SPLIT.split(text):
        rec = part.strip()
        if not rec:
            continue
        m = _HIT_START.match(rec)
        if not m:
            continue
        ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=settings.CST_TZ
        )
        out.append((ts, rec))
    return out


def hits_in_window(path: Path, window_sec: float) -> List[str]:
    """Hit records whose stamp falls in [now - window_sec, now]."""
    now = datetime.now(settings.CST_TZ)
    cutoff = now.timestamp() - window_sec
    return [block for ts, block in iter_hit_records(path) if ts.timestamp() >= cutoff]


def window_label(window_sec: float) -> str:
    if window_sec >= 3600 and abs(window_sec % 3600) < 1:
        n = int(round(window_sec / 3600))
        return f"过去 {n} 小时"
    if window_sec >= 60:
        return f"过去 {int(round(window_sec / 60))} 分钟"
    return f"过去 {int(window_sec)} 秒"
