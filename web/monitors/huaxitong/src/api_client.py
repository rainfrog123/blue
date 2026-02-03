"""
API client for Huaxitong hospital appointment system.
"""
import random
import time
import uuid
from typing import Dict, List, Any, Optional

import requests

from config import settings
from .models import AppointmentEntry


class HuaxitongAPIClient:
    """Client for interacting with the Huaxitong API."""

    def __init__(
        self,
        token: Optional[str] = None,
        access_token: Optional[str] = None,
        cookie: Optional[str] = None,
    ):
        """
        Initialize the API client.

        Args:
            token: API token (defaults to env variable HUAXITONG_TOKEN)
            access_token: Access token (defaults to env variable HUAXITONG_ACCESS_TOKEN)
            cookie: Cookie string (defaults to env variable HUAXITONG_COOKIE)
        """
        self.url = settings.API_URL
        self.token = token or settings.API_TOKEN
        self.access_token = access_token or settings.API_ACCESS_TOKEN
        self.cookie = cookie or settings.API_COOKIE

    def _generate_random_user_agent(self) -> str:
        """Generate a random but realistic User-Agent string."""
        app_version = random.choice(settings.APP_VERSIONS)
        ios_version = random.choice(settings.IOS_VERSIONS)
        scale = random.choice(settings.SCALE_VALUES)

        return f"hua yi tong/{app_version} (iPhone; iOS {ios_version}; Scale/{scale})"

    def _generate_random_uuid(self) -> str:
        """Generate a random UUID."""
        return str(uuid.uuid4()).upper()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with randomized User-Agent and UUID."""
        headers = settings.DEFAULT_HEADERS.copy()
        headers.update({
            "User-Agent": self._generate_random_user_agent(),
            "UUID": self._generate_random_uuid(),
            "token": self.token,
            "accessToken": self.access_token,
            "Cookie": self.cookie,
        })
        return headers

    def _get_payload(self, base_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate payload with current timestamp."""
        payload = base_payload.copy()
        payload["timestamp"] = str(int(time.time()))
        return payload

    def fetch_doctor_appointments(
        self,
        doctor_payload: Dict[str, Any],
        doctor_name: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch appointment data for a specific doctor.

        Args:
            doctor_payload: The API payload for the doctor query
            doctor_name: Name of the doctor (for logging)

        Returns:
            API response as dictionary, or None if request failed
        """
        try:
            # Add small random delay before request (0.5-2 seconds)
            time.sleep(random.uniform(0.5, 2.0))

            payload = self._get_payload(doctor_payload)
            headers = self._get_headers()

            response = requests.post(
                self.url,
                headers=headers,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ HTTP {response.status_code}: {response.text[:100]}...")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Request error for {doctor_name}: {e}")
            return None

    def extract_appointments(
        self,
        data: Dict[str, Any],
        doctor_name: str,
    ) -> List[AppointmentEntry]:
        """
        Extract appointment entries from API response.

        Args:
            data: API response dictionary
            doctor_name: Name of the doctor

        Returns:
            List of AppointmentEntry objects
        """
        if not data or data.get("code") != "1":
            return []

        entries = []
        seen_ids = set()

        def add_entry(item: dict):
            schedule_id = item.get("sysScheduleId")
            if schedule_id and schedule_id not in seen_ids:
                seen_ids.add(schedule_id)
                entries.append(AppointmentEntry.from_api_response(item, doctor_name))

        response_data = data.get("data", {})

        # Process flat list
        for item in response_data.get("sourceItemsRespVos", []) or []:
            add_entry(item)

        # Process nested structure (by hospital area)
        for area in response_data.get("sourceItems", []) or []:
            if area:
                for item in area.get("sourceItemsRespVos", []) or []:
                    add_entry(item)

        return entries
