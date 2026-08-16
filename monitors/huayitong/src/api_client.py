"""HTTP client for the Huayitong (华医通) appointment API."""
from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional

import requests
import urllib3

from config import settings
from .models import AppointmentEntry

if settings.API_PROXY and settings.API_PROXY_INSECURE:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HuayitongAPIClient:
    """POST doctor detail queries with rotating client headers."""

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
                "UUID": str(uuid.uuid4()).upper(),
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
    ) -> Optional[Dict[str, Any]]:
        """Fetch raw JSON for one doctor, or None on failure."""
        try:
            time.sleep(random.uniform(0.5, 2.0))
            payload = dict(doctor_payload)
            payload["timestamp"] = str(int(time.time()))

            kwargs: Dict[str, Any] = {
                "headers": self._headers(),
                "json": payload,
                "timeout": 30,
            }
            if settings.API_PROXY:
                kwargs["proxies"] = {
                    "http": settings.API_PROXY,
                    "https": settings.API_PROXY,
                }
                if settings.API_PROXY_INSECURE:
                    kwargs["verify"] = False

            response = requests.post(self.url, **kwargs)

            if response.status_code != 200:
                print(f"[HTTP {response.status_code}] {doctor_name}: {response.text[:120]}")
                return None

            ctype = (response.headers.get("Content-Type") or "").lower()
            body = response.text or ""
            if "aliyun_waf" in body or ctype.startswith("text/html"):
                print(
                    "[WAF] Aliyun challenge (HTML) instead of JSON. "
                    "From this PC set HUAYITONG_PROXY=http://192.168.23.128:8080 "
                    "(guest mitmweb) — see .env.example."
                )
                return None

            try:
                return response.json()
            except ValueError:
                print(f"[HTTP 200 non-json] {doctor_name}: {body[:120]!r}")
                return None
        except requests.RequestException as exc:
            print(f"[request error] {doctor_name}: {exc}")
            return None

    def extract_appointments(
        self,
        data: Dict[str, Any],
        doctor_name: str,
    ) -> List[AppointmentEntry]:
        """Flatten API response into AppointmentEntry list (deduped by schedule id)."""
        if not data or data.get("code") != "1":
            return []

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
