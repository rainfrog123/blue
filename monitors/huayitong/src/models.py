"""Data models for appointment monitoring."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


STATUS_LABELS = {
    1: "Available",
    2: "Fully Booked",
    3: "Suspended",
}


@dataclass
class AppointmentEntry:
    """One appointment schedule slot from the Huayitong API."""

    id: str
    schedule_date: str
    schedule_range: int
    time_period: str
    remaining_num: int
    available_count: int
    status: int
    dept_name: str
    hospital_area_name: str
    day_desc: str
    adm_location: str
    reg_fee: float
    service_fee: float
    reg_title_name: str
    doctor_name: str = ""
    changes_summary: str = ""

    @property
    def total_fee(self) -> float:
        return self.reg_fee + self.service_fee

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, f"Status {self.status}")

    @property
    def is_bookable(self) -> bool:
        """True when the app would allow booking (either seat field)."""
        return self.status == 1 and (
            self.available_count > 0 or self.remaining_num > 0
        )

    @classmethod
    def from_api_response(cls, item: dict[str, Any], doctor_name: str = "") -> AppointmentEntry:
        schedule_range = int(item.get("scheduleRange") or 0)
        return cls(
            id=str(item.get("sysScheduleId") or ""),
            schedule_date=str(item.get("scheduleDate") or ""),
            schedule_range=schedule_range,
            time_period=_time_period_label(schedule_range),
            remaining_num=int(item.get("remainingNum") or 0),
            available_count=int(item.get("availableCount") or 0),
            status=int(item.get("status") or 0),
            dept_name=str(item.get("deptName") or ""),
            hospital_area_name=str(item.get("hospitalAreaName") or ""),
            day_desc=str(item.get("dayDesc") or ""),
            adm_location=str(item.get("admLocation") or ""),
            reg_fee=float(item.get("regFee") or 0),
            service_fee=float(item.get("serviceFee") or 0),
            reg_title_name=str(item.get("regTitelName") or ""),
            doctor_name=doctor_name,
        )


def _time_period_label(schedule_range: int) -> str:
    if schedule_range == 0:
        return "上午"
    if schedule_range == 1:
        return "下午"
    return f"段{schedule_range}"


@dataclass(frozen=True)
class DoctorConfig:
    name: str
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DoctorConfig:
        return cls(name=data["name"], payload=data["payload"])
