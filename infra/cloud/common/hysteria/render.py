#!/usr/bin/env python3
"""Preview merged Hy2 config: common defaults + <vps>/site.yaml.

Runtime merge is in docker-compose (cat defaults + site). Use --stdout or
default write is disabled — this only prints unless --write is passed.
"""
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
    return (
        f"# merged: common/hysteria/defaults.yaml + {site}/hysteria/site.yaml\n"
        f"{defaults}\n{overlay}"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("site", choices=SITES)
    p.add_argument(
        "--write",
        action="store_true",
        help="also write <vps>/hysteria/config.yaml (optional; compose does not need it)",
    )
    args = p.parse_args()
    text = merge_text(args.site)
    sys.stdout.buffer.write(text.encode("utf-8"))
    if args.write:
        out = ROOT / args.site / "hysteria" / "config.yaml"
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"\n# wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
