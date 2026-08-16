"""Notifier protocol and fan-out."""
from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from ..models import RosterSlot


@runtime_checkable
class Notifier(Protocol):
    async def send(self, slots: List[RosterSlot]) -> bool: ...

    async def test_connection(self) -> bool: ...


class MultiNotifier:
    def __init__(self, notifiers: List[Notifier]) -> None:
        self.notifiers = list(notifiers)

    async def send(self, slots: List[RosterSlot]) -> bool:
        if not self.notifiers:
            print("[warn] No notifiers configured")
            return False
        ok = False
        for notifier in self.notifiers:
            try:
                if await notifier.send(slots):
                    ok = True
            except Exception as exc:
                print(f"[notify error] {type(notifier).__name__}: {exc}")
        return ok

    async def test_connection(self) -> bool:
        if not self.notifiers:
            print("[warn] No notifiers configured")
            return False
        results = [await n.test_connection() for n in self.notifiers]
        return all(results)
