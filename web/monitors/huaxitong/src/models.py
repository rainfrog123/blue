"""
Data models for appointment monitoring.
"""
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class AppointmentEntry:
    """Represents a single appointment slot."""
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
        """Calculate total fee (registration + service)."""
        return self.reg_fee + self.service_fee

    @property
    def status_label(self) -> str:
        """Get human-readable status label."""
        status_map = {1: "Available", 2: "Fully Booked", 3: "Suspended"}
        return status_map.get(self.status, f"Status {self.status}")

    @property
    def is_bookable(self) -> bool:
        """Check if this slot is bookable."""
        return self.status == 1

    @classmethod
    def from_api_response(cls, item: dict, doctor_name: str = "") -> "AppointmentEntry":
        """Create an AppointmentEntry from API response item."""
        schedule_range = item.get("scheduleRange", 0)
        return cls(
            id=item.get("sysScheduleId", ""),
            schedule_date=item.get("scheduleDate", ""),
            schedule_range=schedule_range,
            time_period=cls._get_time_period_label(schedule_range),
            remaining_num=item.get("remainingNum", 0),
            available_count=item.get("availableCount", 0),
            status=item.get("status", 0),
            dept_name=item.get("deptName", ""),
            hospital_area_name=item.get("hospitalAreaName", ""),
            day_desc=item.get("dayDesc", ""),
            adm_location=item.get("admLocation", ""),
            reg_fee=item.get("regFee", 0),
            service_fee=item.get("serviceFee", 0),
            reg_title_name=item.get("regTitelName", ""),
            doctor_name=doctor_name,
        )

    @staticmethod
    def _get_time_period_label(schedule_range: int) -> str:
        """Get time period label based on scheduleRange."""
        if schedule_range == 0:
            return "Morning"
        elif schedule_range == 1:
            return "Afternoon"
        else:
            return f"Period {schedule_range}"


@dataclass
class DoctorConfig:
    """Configuration for a doctor to monitor."""
    name: str
    payload: dict

    @classmethod
    def from_dict(cls, data: dict) -> "DoctorConfig":
        """Create a DoctorConfig from dictionary."""
        return cls(name=data["name"], payload=data["payload"])
