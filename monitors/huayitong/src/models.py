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
        """Open if status is Available *or* either seat field is >0."""
        return (
            self.status == 1
            or self.available_count > 0
            or self.remaining_num > 0
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


_PAYLOAD_DEFAULTS = {
    "hospitalCode": "HID0101",
    "deptCode": "",
    "channelCode": "PATIENT_IOS",
    "appCode": "HXGYAPP",
    "hospitalAreaCode": "",
    "tabAreaCode": "",
    "cardId": "",
    "deptCategoryCode": "",
    "appointmentType": "1",
}


def _truthy(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def _payload_from_row(data: dict[str, Any], uid: str) -> dict[str, Any]:
    if isinstance(data.get("payload"), dict) and data["payload"]:
        body = dict(data["payload"])
        if uid and not body.get("doctorId"):
            body["doctorId"] = uid
        return body
    body = dict(_PAYLOAD_DEFAULTS)
    for key in _PAYLOAD_DEFAULTS:
        if key in data:
            body[key] = data[key]
    body["doctorId"] = uid
    body["encrypt"] = str(data.get("encrypt") or "")
    return body


@dataclass(frozen=True)
class DoctorConfig:
    name: str
    payload: dict[str, Any]
    wecom_hook: str = "gq"
    slug: str = "doctor"
    doctor_id: str = ""
    doc_code: str = ""
    active: bool = True

    @property
    def uid(self) -> str:
        return self.doctor_id

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DoctorConfig:
        hook = str(data.get("hook") or data.get("wecom_hook") or "gq").strip().lower()
        if hook not in ("gq", "cjc"):
            hook = "gq"
        slug = str(data.get("slug") or "").strip().lower()
        name = str(data.get("name") or slug or "doctor")
        if not slug:
            slug = _slug_from_name(name)
        nested = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        doctor_id = str(
            data.get("doctorId")
            or data.get("uid")
            or nested.get("doctorId")
            or ""
        ).strip()
        doc_code = str(data.get("docCode") or data.get("doc_code") or "").strip()
        return cls(
            name=name,
            payload=_payload_from_row(data, doctor_id),
            wecom_hook=hook,
            slug=slug,
            doctor_id=doctor_id,
            doc_code=doc_code,
            active=_truthy(data.get("active"), default=True),
        )


_NAME_SLUGS = {
    "赵宇": "zhaoyu",
    "李正勇": "lizhengyong",
    "伍俊良": "wujunliang",
}


def _slug_from_name(name: str) -> str:
    for prefix, slug in _NAME_SLUGS.items():
        if name.startswith(prefix):
            return slug
    return "doctor"
