"""Track previous slot state to detect newly bookable appointments."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from config import settings
from .models import AppointmentEntry

# (status, available_count, remaining_num)
_Prev = Tuple[int, int, int]


def _bookable(status: int, available_count: int, remaining_num: int) -> bool:
    """Any of these means 'something to book / opened' — not AND."""
    return status == 1 or available_count > 0 or remaining_num > 0


class SlotStateTracker:
    """Remember last status/counts per doctor+schedule id. Persists to state.json."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or settings.STATE_PATH
        self._prev: Dict[str, _Prev] = {}
        self._warm = False
        self.load()

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self._warm = bool(blob.get("warm"))
        prev = blob.get("prev") or {}
        out: Dict[str, _Prev] = {}
        for key, val in prev.items():
            if isinstance(val, list) and len(val) >= 3:
                out[str(key)] = (int(val[0]), int(val[1]), int(val[2]))
        self._prev = out

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "warm": self._warm,
            "prev": {k: list(v) for k, v in self._prev.items()},
        }
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )

    def mark_warm(self) -> None:
        """Call after the first successful poll. Later unseen ids can alert."""
        self._warm = True
        self.save()

    @staticmethod
    def _key(doctor_name: str, schedule_id: str) -> str:
        return f"{doctor_name}:{schedule_id}"

    def newly_bookable(
        self,
        entries: List[AppointmentEntry],
        doctor_name: str,
    ) -> List[AppointmentEntry]:
        """
        Slots that should notify:

        - Known id: remainingNum / availableCount / status changed.
        - New id after warmup: any of status==1 / avail>0 / remain>0.

        Warmup = first successful poll (or existing state.json). That snapshot is
        baseline only — no alert for rows already on the list, even if open.
        """
        changes: List[AppointmentEntry] = []

        for entry in entries:
            key = self._key(doctor_name, entry.id)
            prev = self._prev.get(key)
            self._prev[key] = (
                entry.status,
                entry.available_count,
                entry.remaining_num,
            )

            if prev is None:
                if self._warm and entry.is_bookable:
                    entry.changes_summary = "new slot"
                    changes.append(entry)
                continue

            prev_status, prev_avail, prev_remain = prev
            remain_changed = prev_remain != entry.remaining_num
            avail_changed = prev_avail != entry.available_count
            status_changed = prev_status != entry.status
            became = entry.is_bookable and not _bookable(
                prev_status, prev_avail, prev_remain
            )
            if not (remain_changed or avail_changed or status_changed or became):
                continue

            details = []
            if prev_status != entry.status:
                details.append(f"status: {prev_status} → {entry.status}")
            if prev_avail != entry.available_count:
                details.append(
                    f"availableCount: {prev_avail} → {entry.available_count}"
                )
            if remain_changed:
                details.append(f"remainingNum: {prev_remain} → {entry.remaining_num}")
            entry.changes_summary = ", ".join(details) or "became bookable"
            changes.append(entry)

        self.save()
        return changes
