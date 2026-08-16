"""Track previous remainingNumber per slot to detect newly bookable openings."""
from __future__ import annotations

from typing import Dict, List, Optional

from .models import RosterSlot


class SlotStateTracker:
    def __init__(self) -> None:
        # slot_id -> remaining_number; missing = unseen
        self._prev: Dict[int, int] = {}

    def newly_bookable(self, slots: List[RosterSlot]) -> List[RosterSlot]:
        """
        Return slots that just became bookable (remaining went 0→positive,
        or first seen after baseline is skipped).
        """
        changes: List[RosterSlot] = []
        for slot in slots:
            prev: Optional[int] = self._prev.get(slot.slot_id)
            self._prev[slot.slot_id] = slot.remaining_number

            if prev is None:
                continue  # baseline — no alert on first sighting

            was_bookable = prev > 0
            if slot.is_bookable and not was_bookable:
                slot.changes_summary = f"remaining: {prev} → {slot.remaining_number}"
                changes.append(slot)

        return changes
