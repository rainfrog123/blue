"""Shared helpers for Alibaba Cloud CLIs under infra/cloud/ali."""
from __future__ import annotations

import sys
from pathlib import Path


def ensure_cred_loader() -> Path:
    """Put infra/scripts on sys.path so cred_loader can be imported."""
    scripts = Path(__file__).resolve().parents[2] / "scripts"
    scripts_str = str(scripts)
    if scripts_str not in sys.path:
        sys.path.insert(0, scripts_str)
    return scripts


def load_alibaba() -> dict:
    """Load Alibaba credentials via infra/scripts/cred_loader."""
    ensure_cred_loader()
    from cred_loader import get_alibaba

    return get_alibaba()


def print_header(title: str, *, product: str, region: str, extra: str | None = None) -> None:
    """Print a consistent banner for CLI output."""
    print("=" * 60)
    print(f"ALIBABA CLOUD {product} - {title}")
    print("=" * 60)
    print(f"Region:     {region}")
    if extra:
        print(extra)
    print("=" * 60)
