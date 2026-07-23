#!/usr/bin/env python3
"""Merge common/stacks/ss-rust/defaults.json + hosts/<host>/ss-rust/site.json → config.json."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

STACK = Path(__file__).resolve().parent
CLOUD = STACK.parents[2]
sys.path.insert(0, str(CLOUD / "common" / "lib"))
from jsonutil import deep_merge, dump_json, load_json, write_json  # noqa: E402

HOSTS = ("digi", "ali", "azure")


def merge(host: str) -> dict:
    site_file = CLOUD / "hosts" / host / "ss-rust" / "site.json"
    if not site_file.is_file():
        raise FileNotFoundError(f"missing {site_file}")
    return deep_merge(load_json(STACK / "defaults.json"), load_json(site_file))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", choices=HOSTS)
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args()
    data = merge(args.host)
    if args.stdout:
        sys.stdout.write(dump_json(data))
    else:
        out = CLOUD / "hosts" / args.host / "ss-rust" / "config.json"
        write_json(out, data)
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
