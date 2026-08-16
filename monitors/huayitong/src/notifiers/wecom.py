"""WeCom group webhook notifier — plain text (personal WeChat–friendly)."""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Sequence

import requests

from config import settings
from ..models import AppointmentEntry

_CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"
_PERIOD = {
    "Morning": "上午",
    "Afternoon": "下午",
    "Evening": "晚上",
    "0": "上午",
    "1": "下午",
}


def _period(label: object) -> str:
    s = "" if label is None else str(label).strip()
    return _PERIOD.get(s, s)


def _date_cn(raw: object) -> str:
    s = "" if raw is None else str(raw).strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if not m:
        return s
    y, mo, d = m.group(1), m.group(2), m.group(3)
    now_y = datetime.now(settings.CST_TZ).year
    if int(y) == now_y:
        return f"{int(mo)}月{int(d)}日"
    return f"{y}年{int(mo)}月{int(d)}日"


def _date_sort_key(raw: object) -> str:
    s = "" if raw is None else str(raw).strip()
    return s if re.match(r"^\d{4}-\d{2}-\d{2}", s) else "9999-99-99"


def _mark(n: int) -> str:
    return _CIRCLED[n - 1] if 1 <= n <= 10 else f"{n}."


def _when_line(change: AppointmentEntry) -> str:
    day = change.day_desc or ""
    when = f"{_date_cn(change.schedule_date)} {_period(change.time_period)}"
    if day:
        when = f"{when}（{day}）"
    return when


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

        doctors = " / ".join(by_doctor)
        now_str = datetime.now(settings.CST_TZ).strftime("%H:%M")
        max_slots = max(1, settings.WECOM_MAX_SLOTS)
        shown = ordered[:max_slots]
        hidden = len(ordered) - len(shown)

        lines = [
            "【有号】华西医院",
            f"【共{len(ordered)}个】{doctors}",
            f"【时间】刚刚 · {now_str}",
            "────────────",
        ]

        n = 1
        for change in shown:
            title = change.reg_title_name or ""
            name = change.doctor_name or "未知"
            who = name if not title else f"{name} · {title}"
            place_bits = [x for x in (change.dept_name, change.hospital_area_name) if x]
            place = " · ".join(place_bits)
            loc = change.adm_location or ""
            lines.extend(
                [
                    f"{_mark(n)}【号源】{_when_line(change)}",
                    f"　【剩余】{change.available_count}　【费用】¥{change.total_fee:g}",
                    f"　【医生】{who}",
                ]
            )
            if place:
                lines.append(f"　【科室】{place}")
            if loc:
                lines.append(f"　【地点】{loc}")
            lines.append("────────────")
            n += 1

        if hidden > 0:
            lines.append(f"【更多】…另有 {hidden} 个号源未列出")
        return "\n".join(lines).rstrip() + "\n"

    def _post(self, content: str) -> bool:
        if not self.webhook_url:
            print("[wecom] WECOM_WEBHOOK_URL missing")
            return False
        payload = {"msgtype": "text", "text": {"content": content}}
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
            )
            if response.status_code != 200:
                print(f"[wecom] HTTP {response.status_code}: {response.text[:200]}")
                return False
            result = response.json()
            if result.get("errcode") == 0:
                return True
            print(f"[wecom] error: {result}")
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
        now_str = datetime.now(settings.CST_TZ).strftime("%H:%M")
        content = (
            "【有号】华西医院\n"
            "【共1个】测试\n"
            f"【时间】刚刚 · {now_str}\n"
            "────────────\n"
            "①【号源】8月12日 上午（周二）\n"
            "　【剩余】3　【费用】¥50\n"
            "　【医生】测试医生 · 主任医师\n"
            "　【科室】示例科室 · 华西院区\n"
            "　【地点】门诊楼示例诊区\n"
            "────────────"
        )
        print("[wecom] test -> webhook")
        ok = self._post(content)
        print(f"[wecom] test {'ok' if ok else 'failed'}")
        return ok
