"""WeCom group webhook notifier — plain text (personal WeChat–friendly)."""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Sequence

from config import settings
from ..http import post_json
from ..logging_util import cst_stamp
from ..models import AppointmentEntry

_PERIOD = {
    "Morning": "上午",
    "Afternoon": "下午",
    "Evening": "晚上",
    "0": "上午",
    "1": "下午",
}

_STATUS_CN = {
    1: "有号",
    2: "满号",
    3: "停诊",
}

_BLANK = "—"
_RULE = "────────────"


def _period(label: object) -> str:
    s = "" if label is None else str(label).strip()
    return _PERIOD.get(s, s)


def _date_sort_key(raw: object) -> str:
    s = "" if raw is None else str(raw).strip()
    return s if re.match(r"^\d{4}-\d{2}-\d{2}", s) else "9999-99-99"


def _val(raw: object) -> str:
    s = "" if raw is None else str(raw).strip()
    return s if s else _BLANK


def _field(label: str, raw: object) -> str:
    return f"{label}：{_val(raw)}"


def _status_line(change: AppointmentEntry) -> str:
    cn = _STATUS_CN.get(change.status, "")
    if cn:
        return f"{change.status} {cn}"
    return str(change.status)


def _when(change: AppointmentEntry) -> str:
    return f"{_val(change.schedule_date)} {_period(change.time_period)}".strip()


def _slot_lines(change: AppointmentEntry, n: int) -> List[str]:
    return [
        f"[{n}]",
        _field("医生", change.doctor_name),
        _field("号别", change.reg_title_name),
        _field("科室", change.dept_name),
        _field("院区", change.hospital_area_name),
        _field("日期", _when(change)),
        _field("星期", change.day_desc),
        _field("地点", change.adm_location),
        _field("剩余", change.remaining_num),
        _field("可约", change.available_count),
        _field("费用", f"¥{change.total_fee:g}"),
        _field("状态", _status_line(change)),
        _field("变动", change.changes_summary),
        _field("编号", change.id),
        _RULE,
    ]


class WeComNotifier:
    """POST text to WeCom incoming group webhook (no markdown)."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> None:
        self.webhook_url = webhook_url or settings.WECOM_WEBHOOK_URL
        self.cooldown = cooldown if cooldown is not None else settings.NOTIFICATION_COOLDOWN
        self._last_sent: Dict[str, float] = {}

    def _sorted(self, changes: Sequence[AppointmentEntry]) -> List[AppointmentEntry]:
        return sorted(
            changes,
            key=lambda c: (
                _date_sort_key(c.schedule_date),
                c.schedule_range,
                c.doctor_name or "",
            ),
        )

    def _build_text(self, changes: List[AppointmentEntry]) -> str:
        ordered = self._sorted(changes)
        by_doctor: Dict[str, List[AppointmentEntry]] = {}
        for change in ordered:
            name = change.doctor_name or "未知"
            by_doctor.setdefault(name, []).append(change)

        doctors = "、".join(by_doctor)
        stamp = cst_stamp()
        max_slots = max(1, settings.WECOM_MAX_SLOTS)
        shown = ordered[:max_slots]
        hidden = len(ordered) - len(shown)

        any_open = any(c.is_bookable for c in ordered)
        event = "有号" if any_open else "号变"
        lines = [
            "华西医院 号源通知",
            _RULE,
            _field("时间", f"[{stamp}]"),
            _field("事件", event),
            _field("条数", len(ordered)),
            _field("医生", doctors),
            _RULE,
        ]

        for n, change in enumerate(shown, start=1):
            lines.extend(_slot_lines(change, n))

        if hidden > 0:
            lines.append(_field("其余", f"另有 {hidden} 条未列出"))
        return "\n".join(lines).rstrip() + "\n"

    def send_text(self, content: str) -> bool:
        return self._post(content)

    def _post(self, content: str) -> bool:
        if not self.webhook_url:
            print("[wecom] WECOM_WEBHOOK_URL missing")
            return False
        payload = {"msgtype": "text", "text": {"content": content}}
        try:
            result = post_json(self.webhook_url, payload, timeout=10)
            if result.status != 200:
                print(f"[wecom] HTTP {result.status}: {result.text()[:200]}")
                return False
            data = result.json()
            if data.get("errcode") == 0:
                return True
            print(f"[wecom] error: {data}")
            return False
        except Exception as exc:
            print(f"[wecom] send failed: {exc}")
            return False

    def send(self, changes: List[AppointmentEntry]) -> bool:
        if not changes:
            return False
        now = time.time()
        due: List[AppointmentEntry] = []
        for change in changes:
            last = self._last_sent.get(change.id, 0.0)
            wait = self.cooldown - (now - last)
            if wait > 0:
                print(f"[wecom] cooldown {wait:.0f}s on {change.id}")
                continue
            due.append(change)
        if not due:
            return False
        if self._post(self._build_text(due)):
            sent_at = time.time()
            for change in due:
                self._last_sent[change.id] = sent_at
            print(f"[wecom] sent {len(due)} slot(s)")
            return True
        return False

    def test_connection(self) -> bool:
        stamp = cst_stamp()
        content = (
            "华西医院 号源通知\n"
            f"{_RULE}\n"
            f"时间：[{stamp}]\n"
            "事件：有号\n"
            "条数：1\n"
            "医生：测试\n"
            f"{_RULE}\n"
            "[1]\n"
            "医生：测试医生\n"
            "号别：主任医师\n"
            "科室：示例科室\n"
            "院区：华西院区\n"
            "日期：2026-08-12 上午\n"
            "星期：周三\n"
            "地点：门诊楼示例诊区\n"
            "剩余：3\n"
            "可约：3\n"
            "费用：¥50\n"
            "状态：1 有号\n"
            "变动：status: 2 → 1\n"
            "编号：0\n"
            f"{_RULE}\n"
        )
        print("[wecom] test -> webhook")
        ok = self._post(content)
        print(f"[wecom] test {'ok' if ok else 'failed'}")
        return ok
