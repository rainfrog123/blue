"""ServerChan WeChat push (async)."""
from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional

import aiohttp

from config import settings
from ..models import RosterSlot


class ServerChanNotifier:
    def __init__(
        self,
        url: Optional[str] = None,
        cooldown: Optional[int] = None,
    ) -> None:
        self.url = url or settings.SERVERCHAN_URL
        self.cooldown = cooldown if cooldown is not None else settings.NOTIFICATION_COOLDOWN
        self.last_notification_time = 0.0

    def _on_cooldown(self) -> tuple[bool, float]:
        remaining = self.cooldown - (time.time() - self.last_notification_time)
        return remaining > 0, max(0.0, remaining)

    def _build(self, slots: List[RosterSlot]) -> tuple[str, str, str]:
        by_doctor: Dict[str, List[RosterSlot]] = {}
        for slot in slots:
            by_doctor.setdefault(slot.doctor_name, []).append(slot)

        doctors = ", ".join(by_doctor)
        now_str = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S CST")
        title = f"口腔科预约 - 发现{len(slots)}个空位!"[:32]

        lines = [
            f"## {settings.DEPARTMENT_NAME} 预约信息",
            f"**医生**: {doctors}",
            f"**时间**: {now_str}",
            f"**发现**: {len(slots)} 个可预约时段",
            "",
            "### 可预约时段详情:",
        ]
        n = 1
        for doctor_name, doctor_slots in by_doctor.items():
            title_doc = doctor_slots[0].doctor_title
            lines.extend(["", f"### {doctor_name} ({title_doc})"])
            for slot in doctor_slots:
                lines.extend(
                    [
                        "",
                        f"**时段 {n}:**",
                        f"- 日期: {slot.date} {slot.time_interval} ({slot.day_of_week})",
                        f"- 科室: {settings.DEPARTMENT_NAME}",
                        f"- 可预约: {slot.remaining_number}/{slot.total_number}",
                        f"- 费用: ¥{slot.appointment_amount}",
                        f"- 时段ID: {slot.slot_id}",
                    ]
                )
                n += 1
        lines.extend(["", "---", "请尽快在华西口腔微信小程序预约。"])
        short = (
            f"发现{len(slots)}个时段 - {slots[0].doctor_name} "
            f"{slots[0].date} {slots[0].time_interval}"
        )[:64]
        return title, "\n".join(lines), short

    async def send(self, slots: List[RosterSlot]) -> bool:
        if not slots or not self.url:
            return False
        cooling, remaining = self._on_cooldown()
        if cooling:
            print(f"[serverchan] cooldown {remaining:.0f}s")
            return False

        title, desp, short = self._build(slots)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    data={"title": title, "desp": desp, "short": short, "noip": "1"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        print(f"[serverchan] HTTP {resp.status}")
                        return False
                    result = await resp.json()
                    if result.get("errno") == 0 or result.get("code") == 0:
                        self.last_notification_time = time.time()
                        print(
                            f"[serverchan] sent pushid="
                            f"{result.get('data', {}).get('pushid')}"
                        )
                        return True
                    print(f"[serverchan] error: {result}")
                    return False
        except Exception as exc:
            print(f"[serverchan] failed: {exc}")
            return False

    async def test_connection(self) -> bool:
        now = datetime.now(settings.CST_TZ).strftime("%Y-%m-%d %H:%M:%S")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    data={
                        "title": "Hxkq ServerChan Test",
                        "desp": f"## Test\n\n**Time**: {now}\n\n华西口腔 monitor OK.",
                        "short": "hxkq test",
                        "noip": "1",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json() if resp.status == 200 else {}
                    ok = resp.status == 200 and (
                        result.get("errno") == 0 or result.get("code") == 0
                    )
                    print(f"[serverchan] test {'ok' if ok else 'failed'}: {result}")
                    return bool(ok)
        except Exception as exc:
            print(f"[serverchan] test failed: {exc}")
            return False
