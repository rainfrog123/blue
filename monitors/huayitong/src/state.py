"""Track previous slot state to detect newly bookable appointments."""
from __future__ import annotations

from typing import Dict, List, Tuple

from .models import AppointmentEntry

# (status, available_count, remaining_num)
_Prev = Tuple[int, int, int]


def _bookable(status: int, available_count: int, remaining_num: int) -> bool:
    return status == 1 and (available_count > 0 or remaining_num > 0)


class SlotStateTracker:
    """Remember last status/counts per doctor+schedule id."""

    def __init__(self) -> None:
        self._prev: Dict[str, _Prev] = {}
        self._warm = False

    def mark_warm(self) -> None:
        """Call after the first successful poll. Later unseen ids can alert."""
        self._warm = True

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

        - Known id: remainingNum changed (any direction).
        - Known id: was not bookable, now is (status 2→1 / avail 0→N).
        - New id after warmup: appears already bookable (放号 of a new date).

        First successful poll is baseline only (no alert), even if seats exist.
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

        return changes
