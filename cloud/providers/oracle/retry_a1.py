#!/usr/bin/env python3
"""
Retry Always Free Ampere A1 until Tokyo (or any home region) has capacity.

Same idea as community oci-arm-catcher: launch in a loop, retry only on
Out of host capacity / 429 / 500, stop on real config errors.

Examples (from blue repo root):

  /c/v/oci/Scripts/python cloud/providers/oracle/Retry-A1.py
  /c/v/oci/Scripts/python cloud/providers/oracle/Retry-A1.py --ocpus 1 --memory 6
  /c/v/oci/Scripts/python cloud/providers/oracle/Retry-A1.py --interval 45 --max 0
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oci.exceptions import ServiceError

import helpers

# Same group webhook as WeCom Push Setup (monitors). Override with WECOM_WEBHOOK_URL.
_DEFAULT_WECOM_WEBHOOK = (
    "https://qyapi.weixin.qq.com/cgi-bin/webhook/send"
    "?key=685b4dce-8bbc-4d64-9de1-36027e8bc5d1"
)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _log(msg: str) -> None:
    print(f"[{_ts()}] {msg}", flush=True)


def _notify_wecom(content: str, webhook_url: str | None) -> None:
    """POST plain text to WeCom group webhook. Never raises."""
    url = (webhook_url or "").strip() or os.environ.get(
        "WECOM_WEBHOOK_URL", _DEFAULT_WECOM_WEBHOOK
    )
    if not url:
        _log("wecom: skipped (no webhook URL)")
        return
    body = json.dumps(
        {"msgtype": "text", "text": {"content": content}},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            result = {"raw": raw}
        if result.get("errcode", 0) != 0:
            _log(f"wecom: failed {result}")
        else:
            _log("wecom: sent success alert")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        _log(f"wecom: send failed: {exc}")


def _is_capacity_error(exc: BaseException) -> bool:
    if not isinstance(exc, ServiceError):
        return False
    msg = (exc.message or "").lower()
    return (
        exc.status in (429, 500)
        or "out of host capacity" in msg
        or "out of capacity" in msg
        or "internal error" in msg
        or "too many requests" in msg
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Retry launch of Always Free VM.Standard.A1.Flex until capacity appears"
    )
    p.add_argument("-n", "--name", default="a1-free-tokyo", help="Display name")
    p.add_argument("--ocpus", type=float, default=2.0, help="OCPUs (Always Free max 2 total)")
    p.add_argument("--memory", type=float, default=12.0, help="Memory GB (Always Free max 12 total)")
    p.add_argument("--boot", type=int, default=50, help="Boot volume GB")
    p.add_argument("--subnet", help="Subnet OCID (default: first public-ish subnet)")
    p.add_argument("--ad", action="append", dest="ads", help="AD name (repeat to rotate)")
    p.add_argument("--ssh-key", help="Path to SSH public key")
    p.add_argument("--version", default="22.04", help="Ubuntu version for image")
    p.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between capacity retries (default 60)",
    )
    p.add_argument(
        "--max",
        type=int,
        default=0,
        help="Max attempts (0 = forever)",
    )
    p.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for RUNNING after launch",
    )
    p.add_argument(
        "--foothold",
        action="store_true",
        help="Shortcut: 1 OCPU / 6 GB (easier to land, resize later)",
    )
    p.add_argument(
        "--no-wecom",
        action="store_true",
        help="Do not push WeCom webhook on successful launch",
    )
    p.add_argument(
        "--wecom-webhook",
        default=None,
        help="WeCom webhook URL (default: WECOM_WEBHOOK_URL or vault default)",
    )
    args = p.parse_args()

    if args.foothold:
        args.ocpus = 1.0
        args.memory = 6.0

    cfg, identity, compute, network = helpers.get_clients()
    comp = helpers.compartment_id(cfg)

    ad_list = args.ads
    if not ad_list:
        ad_list = [ad.name for ad in helpers.list_availability_domains(identity, comp)]
    if not ad_list:
        _log("ERROR: no availability domains")
        return 1

    subnet = helpers.pick_subnet(network, comp, args.subnet)
    image = helpers.latest_ubuntu_image(
        compute, comp, "VM.Standard.A1.Flex", version=args.version
    )
    ssh_pub = helpers.read_ssh_pub(args.ssh_key)

    _log("Oracle A1 capacity catcher")
    _log(f"  region={cfg['region']} tenancy={cfg['tenancy'][:28]}...")
    _log(f"  name={args.name} shape=VM.Standard.A1.Flex {args.ocpus} OCPU / {args.memory} GB")
    _log(f"  boot={args.boot}G interval={args.interval}s max={args.max or 'forever'}")
    _log(f"  ADs={', '.join(ad_list)}")
    _log(f"  subnet={subnet.display_name}")
    _log(f"  image={image.display_name}")

    attempt = 0
    while True:
        attempt += 1
        if args.max and attempt > args.max:
            _log(f"Gave up after {args.max} attempts")
            return 2

        ad = ad_list[(attempt - 1) % len(ad_list)]
        _log(f"attempt {attempt}: launch in {ad}")

        try:
            inst = helpers.launch_instance(
                compute,
                compartment=comp,
                availability_domain=ad,
                shape="VM.Standard.A1.Flex",
                ocpus=args.ocpus,
                memory_in_gbs=args.memory,
                image_id=image.id,
                subnet_id=subnet.id,
                display_name=args.name,
                ssh_pub=ssh_pub,
                boot_gb=args.boot,
                assign_public_ip=True,
            )
        except ServiceError as e:
            if _is_capacity_error(e):
                _log(f"  capacity ({e.status}): {e.message}")
                _log(f"  sleep {args.interval}s")
                time.sleep(args.interval)
                continue
            _log(f"ERROR (not retrying): status={e.status} code={e.code} {e.message}")
            return 1
        except SystemExit as e:
            _log(f"ERROR: {e}")
            return 1

        _log(f"LAUNCHED {inst.id} state={inst.lifecycle_state}")

        ips: list[str] = []
        if not args.no_wait:
            _log("waiting for RUNNING...")
            try:
                inst = helpers.wait_instance_state(compute, inst.id, {"RUNNING"})
            except TimeoutError as e:
                _log(f"WARN: {e}")
            ips = helpers.public_ips_for_instance(compute, network, comp, inst.id)
            _log(f"RUNNING ips={', '.join(ips) if ips else 'N/A'}")
            if ips and not str(ips[0]).startswith("priv:"):
                _log(f"SSH: ssh ubuntu@{ips[0]}")

        if args.foothold:
            _log("Foothold size 1/6 — resize to 2/12 in Console or CLI when ready")

        if not args.no_wecom:
            lines = [
                "【Oracle A1】LAUNCHED",
                f"name={args.name}",
                f"region={cfg['region']} AD={ad}",
                f"shape=VM.Standard.A1.Flex {args.ocpus:g} OCPU / {args.memory:g} GB",
                f"state={inst.lifecycle_state}",
                f"attempts={attempt}",
                f"id={inst.id}",
            ]
            if ips:
                lines.append(f"ips={', '.join(ips)}")
                pub = next(
                    (ip for ip in ips if not str(ip).startswith("priv:")), None
                )
                if pub:
                    lines.append(f"SSH: ssh ubuntu@{pub}")
            if args.foothold:
                lines.append("foothold 1/6 — resize to 2/12 when ready")
            _notify_wecom("\n".join(lines), args.wecom_webhook)

        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        _log("interrupted")
        raise SystemExit(130)
