#!/usr/bin/env python3
"""Deep-merge JSON helpers for common proxy defaults + per-VPS site.json."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = dict(base)
        for key, val in overlay.items():
            out[key] = deep_merge(out[key], val) if key in out else val
        return out
    return overlay


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def write_json(path: Path, data: Any) -> None:
    path.write_text(dump_json(data), encoding="utf-8", newline="\n")
