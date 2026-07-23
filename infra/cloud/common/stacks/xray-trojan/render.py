#!/usr/bin/env python3
"""Build xray-trojan config.json from common defaults + hosts/<host>/site.json."""
from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

STACK = Path(__file__).resolve().parent
CLOUD = STACK.parents[2]
sys.path.insert(0, str(CLOUD / "common" / "lib"))
from jsonutil import dump_json, load_json, write_json  # noqa: E402

HOSTS = ("digi", "ali", "azure")
REQUIRED = ("password", "email", "path")


def merge(host: str) -> dict:
    site_file = CLOUD / "hosts" / host / "xray-trojan" / "site.json"
    if not site_file.is_file():
        raise FileNotFoundError(f"missing {site_file}")
    site_cfg = load_json(site_file)
    missing = [k for k in REQUIRED if k not in site_cfg]
    if missing:
        raise SystemExit(f"{site_file}: missing keys {missing}")
    cfg = copy.deepcopy(load_json(STACK / "defaults.json"))
    inbound = cfg["inbounds"][0]
    inbound["port"] = int(site_cfg.get("port", inbound["port"]))
    inbound["settings"]["clients"][0]["password"] = site_cfg["password"]
    inbound["settings"]["clients"][0]["email"] = site_cfg["email"]
    inbound["streamSettings"]["wsSettings"]["path"] = site_cfg["path"]
    if "loglevel" in site_cfg:
        cfg["log"]["loglevel"] = site_cfg["loglevel"]
    return cfg


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", choices=HOSTS)
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args()
    data = merge(args.host)
    if args.stdout:
        sys.stdout.write(dump_json(data))
    else:
        out = CLOUD / "hosts" / args.host / "xray-trojan" / "config.json"
        write_json(out, data)
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
