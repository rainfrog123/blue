"""Data models for stomatology roster monitoring."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DoctorInfo:
    id: int
    name: str
    job_title: str
    department_name: str
    appointment_count: int = 0
    star: Any = None

    @classmethod
    def from_api(cls, item: dict[str, Any]) -> DoctorInfo:
        return cls(
            id=int(item["id"]),
            name=str(item.get("name") or ""),
            job_title=str(item.get("jobTitle") or ""),
            department_name=str(item.get("departmentName") or ""),
            appointment_count=int(item.get("appointmentCount") or 0),
            star=item.get("star"),
        )


@dataclass
class RosterSlot:
    doctor_id: int
    doctor_name: str
    doctor_title: str
    slot_id: int
    date: str
    day_of_week: str
    time_interval: str
    total_number: int
    remaining_number: int
    appointment_amount: float
    changes_summary: str = ""

    @property
    def is_bookable(self) -> bool:
        return self.remaining_number > 0

    @classmethod
    def from_api(
        cls,
        slot: dict[str, Any],
        doctor: DoctorInfo,
    ) -> RosterSlot:
        return cls(
            doctor_id=doctor.id,
            doctor_name=doctor.name,
            doctor_title=doctor.job_title,
            slot_id=int(slot["id"]),
            date=str(slot.get("date") or ""),
            day_of_week=str(slot.get("dayOfWeek") or ""),
            time_interval=str(slot.get("timeInterval") or ""),
            total_number=int(slot.get("totalNumber") or 0),
            remaining_number=int(slot.get("remainingNumber") or 0),
            appointment_amount=float(slot.get("appointmentAmount") or 0),
        )
