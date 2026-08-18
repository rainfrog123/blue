"""Load doctor watch list from `doctors.json`."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

DOCTORS_JSON = Path(__file__).resolve().parent / "doctors.json"


def _truthy(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}


def load_doctor_records() -> list[dict[str, Any]]:
    blob = json.loads(DOCTORS_JSON.read_text(encoding="utf-8"))
    if isinstance(blob, list):
        rows = blob
    elif isinstance(blob, dict):
        rows = blob.get("doctors") or []
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def iter_start_rows() -> Iterable[tuple[str, bool]]:
    """(slug, active) for tmux start/stop."""
    for row in load_doctor_records():
        slug = str(row.get("slug") or "").strip()
        if slug:
            yield slug, _truthy(row.get("active"), default=True)


ALL_DOCTORS = load_doctor_records()
DOCTORS = [row for row in ALL_DOCTORS if _truthy(row.get("active"), default=True)]
