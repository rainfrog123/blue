"""Notifier protocol and fan-out helper."""
from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from ..models import AppointmentEntry


@runtime_checkable
class Notifier(Protocol):
    def send(self, changes: List[AppointmentEntry]) -> bool: ...

    def test_connection(self) -> bool: ...


class MultiNotifier:
    """Send through every configured notifier (best-effort)."""

    def __init__(self, notifiers: List[Notifier]) -> None:
        self.notifiers = list(notifiers)

    def send(self, changes: List[AppointmentEntry]) -> bool:
        if not self.notifiers:
            print("[warn] No notifiers configured")
            return False
        ok = False
        for notifier in self.notifiers:
            try:
                if notifier.send(changes):
                    ok = True
            except Exception as exc:
                print(f"[notify error] {type(notifier).__name__}: {exc}")
        return ok

    def test_connection(self) -> bool:
        if not self.notifiers:
            print("[warn] No notifiers configured")
            return False
        return all(n.test_connection() for n in self.notifiers)
