#!/usr/bin/env python3
"""Merge common/ss-rust/defaults.json + <vps>/ss-rust/site.json → config.json."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parent
CLOUD = COMMON.parent.parent  # infra/cloud
sys.path.insert(0, str(COMMON.parent))  # infra/cloud/common
from jsonutil import deep_merge, dump_json, load_json, write_json  # noqa: E402

SITES = ("digi", "ali", "azure")


def merge(site: str) -> dict:
    site_file = CLOUD / site / "ss-rust" / "site.json"
    if not site_file.is_file():
        raise FileNotFoundError(f"missing {site_file}")
    return deep_merge(load_json(COMMON / "defaults.json"), load_json(site_file))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("site", choices=SITES)
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args()
    data = merge(args.site)
    if args.stdout:
        sys.stdout.write(dump_json(data))
    else:
        out = CLOUD / args.site / "ss-rust" / "config.json"
        write_json(out, data)
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
