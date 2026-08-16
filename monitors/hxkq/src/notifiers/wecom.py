"""WeCom group webhook notifier (async) — plain text (personal WeChat–friendly)."""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Sequence

import aiohttp

from config import settings
from ..models import RosterSlot

_CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩"


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


def _when_line(slot: RosterSlot) -> str:
    when = f"{_date_cn(slot.date)} {slot.time_interval}"
    if slot.day_of_week:
        when = f"{when}（{slot.day_of_week}）"
    return when


class WeComNotifier:
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> None:
        self.webhook_url = webhook_url or settings.WECOM_WEBHOOK_URL
        self.cooldown = cooldown if cooldown is not None else settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0.0

    def _on_cooldown(self) -> tuple[bool, float]:
        remaining = self.cooldown - (time.time() - self.last_notification_time)
        return remaining > 0, max(0.0, remaining)

    def _sorted(self, slots: Sequence[RosterSlot]) -> List[RosterSlot]:
        return sorted(
            slots,
            key=lambda s: (_date_sort_key(s.date), s.time_interval, s.doctor_name),
        )

    def _build_text(self, slots: List[RosterSlot]) -> str:
        ordered = self._sorted(slots)
        by_doctor: Dict[str, List[RosterSlot]] = {}
        for slot in ordered:
            by_doctor.setdefault(slot.doctor_name, []).append(slot)

        doctors = " / ".join(by_doctor)
        now_str = datetime.now(settings.CST_TZ).strftime("%H:%M")
        max_slots = max(1, settings.WECOM_MAX_SLOTS)
        shown = ordered[:max_slots]
        hidden = len(ordered) - len(shown)

        lines = [
            "【有号】华西口腔",
            f"【科室】{settings.DEPARTMENT_NAME}",
            f"【共{len(ordered)}个】{doctors}",
            f"【时间】刚刚 · {now_str}",
            "────────────",
        ]

        n = 1
        for slot in shown:
            title = slot.doctor_title
            who = slot.doctor_name if not title else f"{slot.doctor_name} · {title}"
            lines.extend(
                [
                    f"{_mark(n)}【号源】{_when_line(slot)}",
                    f"　【剩余】{slot.remaining_number}/{slot.total_number}　【费用】¥{slot.appointment_amount:g}",
                    f"　【医生】{who}",
                    "────────────",
                ]
            )
            n += 1

        if hidden > 0:
            lines.append(f"【更多】…另有 {hidden} 个号源未列出")
        return "\n".join(lines).rstrip() + "\n"

    async def _post(self, content: str) -> bool:
        if not self.webhook_url:
            print("[wecom] WECOM_WEBHOOK_URL missing")
            return False
        payload = {"msgtype": "text", "text": {"content": content}}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json() if resp.status == 200 else {}
                    if resp.status == 200 and result.get("errcode") == 0:
                        return True
                    print(f"[wecom] failed: {resp.status} {result}")
                    return False
        except Exception as exc:
            print(f"[wecom] failed: {exc}")
            return False

    async def send(self, slots: List[RosterSlot]) -> bool:
        if not slots:
            return False
        cooling, remaining = self._on_cooldown()
        if cooling:
            print(f"[wecom] cooldown {remaining:.0f}s")
            return False
        if await self._post(self._build_text(slots)):
            self.last_notification_time = time.time()
            print(f"[wecom] sent {len(slots)} slot(s)")
            return True
        return False

    async def test_connection(self) -> bool:
        now = datetime.now(settings.CST_TZ).strftime("%H:%M")
        content = (
            "【有号】华西口腔\n"
            f"【科室】{settings.DEPARTMENT_NAME}\n"
            "【共1个】测试\n"
            f"【时间】刚刚 · {now}\n"
            "────────────\n"
            "①【号源】8月12日 09:00-12:00（周二）\n"
            "　【剩余】3/10　【费用】¥50\n"
            "　【医生】测试医生 · 主任医师\n"
            "────────────"
        )
        ok = await self._post(content)
        print(f"[wecom] test {'ok' if ok else 'failed'}")
        return ok
