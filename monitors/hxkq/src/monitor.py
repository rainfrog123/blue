"""Async polling loop for Huaxi Stomatology rosters."""
from __future__ import annotations

import asyncio
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import aiohttp

from config import settings
from .api_client import HxkqAPIClient
from .logging_util import (
    log_regular,
    log_success,
    session_end,
    session_start,
)
from .models import DoctorInfo, RosterSlot
from .notifiers import MultiNotifier, build_notifiers
from .state import SlotStateTracker


class StomatologyMonitor:
    def __init__(
        self,
        api: Optional[HxkqAPIClient] = None,
        notifier: Optional[MultiNotifier] = None,
    ) -> None:
        self.api = api or HxkqAPIClient()
        self.notifier = notifier or build_notifiers()
        self.state = SlotStateTracker()
        self.doctors: Dict[int, DoctorInfo] = {}

    async def check_once(
        self,
        session: aiohttp.ClientSession,
    ) -> Tuple[List[RosterSlot], List[RosterSlot]]:
        tasks = [
            self.api.get_roster(session, doctor)
            for doctor in self.doctors.values()
        ]
        results = await asyncio.gather(*tasks)

        all_slots: List[RosterSlot] = []
        changes: List[RosterSlot] = []
        for roster in results:
            all_slots.extend(roster)
            changes.extend(self.state.newly_bookable(roster))
        return all_slots, changes

    async def refresh_doctors(self, session: aiohttp.ClientSession) -> None:
        previous = dict(self.doctors)
        fresh = await self.api.collect_doctors(session)
        if not fresh:
            print("[warn] doctor refresh empty — keeping previous list")
            return
        self.doctors = fresh
        added = [d for i, d in fresh.items() if i not in previous]
        removed = [d for i, d in previous.items() if i not in fresh]
        print(f"[ok] doctors {len(previous)} → {len(fresh)}")
        for d in added:
            print(f"  + {d.name} ({d.job_title}) id={d.id}")
        for d in removed:
            print(f"  - {d.name} ({d.job_title}) id={d.id}")

    def _print_changes(self, changes: List[RosterSlot]) -> None:
        print(f"\n*** {len(changes)} NEWLY BOOKABLE SLOT(S) ***")
        for slot in changes:
            print(
                f"  Dr. {slot.doctor_name} ({slot.doctor_title}) | "
                f"{slot.date} {slot.time_interval} ({slot.day_of_week}) | "
                f"{slot.remaining_number}/{slot.total_number} | ¥{slot.appointment_amount}"
            )
        print("=" * 60)

    async def run_once(self) -> List[RosterSlot]:
        async with aiohttp.ClientSession() as session:
            if not self.doctors:
                self.doctors = await self.api.collect_doctors(session)
            if not self.doctors:
                print("[error] No doctors found")
                return []
            slots, changes = await self.check_once(session)

        bookable = [s for s in slots if s.is_bookable]
        print(
            f"[ok] {len(self.doctors)} doctors, "
            f"{len(bookable)} currently bookable / {len(slots)} roster rows"
        )
        for slot in bookable:
            print(
                f"  - {slot.doctor_name}: {slot.date} {slot.time_interval} "
                f"({slot.remaining_number}/{slot.total_number})"
            )

        if changes:
            self._print_changes(changes)
            log_success(changes)
            await self.notifier.send(changes)
        else:
            log_regular(len(self.doctors), len(bookable))
        return changes

    async def run(self) -> None:
        session_start()
        print("Starting Huaxi Stomatology (hxkq) monitor…")
        print(f"Department: {settings.DEPARTMENT_NAME} (id={settings.DEPARTMENT_ID})")
        print(f"Interval: {settings.CHECK_INTERVAL}s")
        print(f"Notifiers: {settings.ENABLED_NOTIFIERS}")
        print("Alert rule: newly bookable only (remaining 0→>0); first sighting = baseline")
        print("=" * 60)

        async with aiohttp.ClientSession() as session:
            self.doctors = await self.api.collect_doctors(session)
            if not self.doctors:
                print("[error] No doctors found — exiting")
                session_end()
                return
            for i, doc in enumerate(self.doctors.values(), 1):
                print(f"  {i}. {doc.name} ({doc.job_title}) id={doc.id}")

        iteration = 0
        while True:
            try:
                iteration += 1
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                print(f"\n[{stamp}] Check #{iteration}")

                if iteration > 1 and iteration % settings.DOCTOR_REFRESH_EVERY == 0:
                    async with aiohttp.ClientSession() as session:
                        await self.refresh_doctors(session)

                await self.run_once()

                print(f"[{stamp}] sleep {settings.CHECK_INTERVAL}s")
                await asyncio.sleep(settings.CHECK_INTERVAL)
            except KeyboardInterrupt:
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                print(f"\nStopped by user at {stamp}")
                session_end()
                break
            except Exception as exc:
                stamp = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
                wait = random.uniform(settings.ERROR_WAIT_MIN, settings.ERROR_WAIT_MAX)
                print(f"[{stamp}] Error: {exc}")
                print(f"[{stamp}] Retry in {wait:.1f}s")
                await asyncio.sleep(wait)
