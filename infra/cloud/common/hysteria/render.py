#!/usr/bin/env python3
"""Preview merged Hy2 config (common defaults.yaml + <vps>/site.yaml) on stdout."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parent
ROOT = COMMON.parent.parent  # infra/cloud
SITES = ("digi", "ali", "azure")


def merge_text(site: str) -> str:
    site_file = ROOT / site / "hysteria" / "site.yaml"
    if not site_file.is_file():
        raise FileNotFoundError(f"missing {site_file}")
    defaults = (COMMON / "defaults.yaml").read_text(encoding="utf-8").rstrip() + "\n"
    overlay = site_file.read_text(encoding="utf-8").strip() + "\n"
    # Keys must not overlap between defaults and site (compose cats the two files).
    return (
        f"# preview: common/hysteria/defaults.yaml + {site}/hysteria/site.yaml\n"
        f"{defaults}\n{overlay}"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("site", choices=SITES)
    args = p.parse_args()
    sys.stdout.write(merge_text(args.site))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
