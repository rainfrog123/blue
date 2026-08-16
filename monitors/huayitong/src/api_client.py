"""HTTP client for the Huayitong (华医通) appointment API."""
from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional

from config import settings
from .http import parse_api_json, post_json
from .models import AppointmentEntry


class HuayitongAPIClient:
    """POST doctor detail queries. Transport is CFNetwork on iPhone, urllib elsewhere."""

    def __init__(
        self,
        token: Optional[str] = None,
        access_token: Optional[str] = None,
        cookie: Optional[str] = None,
        url: Optional[str] = None,
    ) -> None:
        self.url = url or settings.API_URL
        self.token = token if token is not None else settings.API_TOKEN
        self.access_token = (
            access_token if access_token is not None else settings.API_ACCESS_TOKEN
        )
        self.cookie = cookie if cookie is not None else settings.API_COOKIE

    def _user_agent(self) -> str:
        app_version = random.choice(settings.APP_VERSIONS)
        ios_version = random.choice(settings.IOS_VERSIONS)
        scale = random.choice(settings.SCALE_VALUES)
        return f"hua yi tong/{app_version} (iPhone; iOS {ios_version}; Scale/{scale})"

    def _headers(self) -> Dict[str, str]:
        headers = dict(settings.DEFAULT_HEADERS)
        headers.update(
            {
                "User-Agent": self._user_agent(),
                "UUID": settings.API_UUID or str(uuid.uuid4()).upper(),
                "token": self.token,
                "accessToken": self.access_token,
                "Cookie": self.cookie,
            }
        )
        return headers

    def fetch_doctor_appointments(
        self,
        doctor_payload: Dict[str, Any],
        doctor_name: str,
    ) -> Dict[str, Any]:
        payload = dict(doctor_payload)
        payload["timestamp"] = str(int(time.time()))
        result = post_json(self.url, payload, self._headers(), timeout=30)
        return parse_api_json(result, doctor_name)

    def extract_appointments(
        self,
        data: Dict[str, Any],
        doctor_name: str,
    ) -> List[AppointmentEntry]:
        """Flatten API response into AppointmentEntry list (deduped by schedule id)."""
        entries: List[AppointmentEntry] = []
        seen: set[str] = set()

        def add(item: dict) -> None:
            schedule_id = item.get("sysScheduleId")
            if not schedule_id or schedule_id in seen:
                return
            seen.add(schedule_id)
            entries.append(AppointmentEntry.from_api_response(item, doctor_name))

        response_data = data.get("data") or {}

        for item in response_data.get("sourceItemsRespVos") or []:
            add(item)

        for area in response_data.get("sourceItems") or []:
            if not area:
                continue
            for item in area.get("sourceItemsRespVos") or []:
                add(item)

        return entries
