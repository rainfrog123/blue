"""Async HTTP client for 华西口腔 WeChat mini-program APIs."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List

import aiohttp

from config import settings
from .models import DoctorInfo, RosterSlot


class HxkqAPIClient:
    def __init__(
        self,
        base_url: str | None = None,
        headers: dict | None = None,
        department_id: int | None = None,
    ) -> None:
        self.base_url = (base_url or settings.API_BASE_URL).rstrip("/")
        self.headers = dict(headers or settings.DEFAULT_HEADERS)
        self.department_id = (
            department_id if department_id is not None else settings.DEPARTMENT_ID
        )

    @staticmethod
    def date_range(start: str, days: int) -> List[str]:
        start_dt = datetime.strptime(start, "%Y-%m-%d")
        return [
            (start_dt + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)
        ]

    async def get_doctor_list(
        self,
        session: aiohttp.ClientSession,
        date: str,
    ) -> List[DoctorInfo]:
        url = f"{self.base_url}/doctor/findDoctorList.web"
        params = {
            "rosterIsNull": 1,
            "pageIndex": 0,
            "pageSize": 20,
            "date": date,
            "professional": "",
            "zn": 1,
            "realAreaCode": "",
            "departmentId": self.department_id,
            "tokenData": "",
        }
        try:
            async with session.get(url, params=params, headers=self.headers) as resp:
                resp.raise_for_status()
                data = await resp.json()
                if data.get("code") != 1 or "data" not in data:
                    return []
                return [
                    DoctorInfo.from_api(item)
                    for item in data["data"].get("content") or []
                ]
        except (aiohttp.ClientError, ValueError) as exc:
            print(f"[api] doctor list {date}: {exc}")
            return []

    async def get_roster(
        self,
        session: aiohttp.ClientSession,
        doctor: DoctorInfo,
    ) -> List[RosterSlot]:
        url = f"{self.base_url}/dutyRoster/findByRoster.web"
        try:
            async with session.get(
                url, params={"doctorId": doctor.id}, headers=self.headers
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                if data.get("code") != 1:
                    return []
                return [
                    RosterSlot.from_api(slot, doctor)
                    for slot in data.get("data") or []
                ]
        except (aiohttp.ClientError, ValueError) as exc:
            print(f"[api] roster {doctor.name}: {exc}")
            return []

    async def collect_doctors(
        self,
        session: aiohttp.ClientSession,
        days: int | None = None,
    ) -> Dict[int, DoctorInfo]:
        days = days if days is not None else settings.DOCTOR_LOOKAHEAD_DAYS
        start = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d")
        dates = self.date_range(start, days)
        print(f"[api] collecting doctors for {len(dates)} days…")

        results = await asyncio.gather(
            *[self.get_doctor_list(session, d) for d in dates]
        )

        doctors: Dict[int, DoctorInfo] = {}
        for day_list in results:
            for doc in day_list:
                doctors.setdefault(doc.id, doc)
        print(f"[api] {len(doctors)} unique doctors")
        return doctors
