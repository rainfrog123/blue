#!/usr/bin/env python3
"""Preview: common/stacks/hysteria/defaults.yaml + hosts/<host>/hysteria/site.yaml."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

STACK = Path(__file__).resolve().parent
CLOUD = STACK.parents[2]  # infra/cloud
HOSTS = ("digi", "ali", "azure")


def merge_text(host: str) -> str:
    site_file = CLOUD / "hosts" / host / "hysteria" / "site.yaml"
    if not site_file.is_file():
        raise FileNotFoundError(f"missing {site_file}")
    defaults = (STACK / "defaults.yaml").read_text(encoding="utf-8").rstrip() + "\n"
    overlay = site_file.read_text(encoding="utf-8").strip() + "\n"
    return (
        f"# preview: common/stacks/hysteria/defaults.yaml + hosts/{host}/hysteria/site.yaml\n"
        f"{defaults}\n{overlay}"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", choices=HOSTS)
    args = p.parse_args()
    sys.stdout.write(merge_text(args.host))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
