#!/usr/bin/env python3
"""
CLI for managing Alibaba Cloud SWAS (轻量应用服务器) instances.

Usage:
    python cli.py info
    python cli.py list
    python cli.py start|stop|reboot
    python cli.py traffic
    python cli.py snapshots
    python cli.py snapshot create [--name NAME]
    python cli.py snapshot delete --id SNAP_ID
    python cli.py images
    python cli.py image list|create|delete
    python cli.py disks
    python cli.py firewall [list|add --port PORT]
    python cli.py run --cmd "uname -a"
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Shared helpers live one level up (cloud/providers/alibaba/common.py)
_ali_root = Path(__file__).resolve().parents[1]
if str(_ali_root) not in sys.path:
    sys.path.insert(0, str(_ali_root))
from common import load_alibaba, print_header as _print_header

from alibabacloud_swas_open20200601 import models as swas_models
from alibabacloud_swas_open20200601.client import Client as SwasClient
from alibabacloud_tea_openapi import models as open_api_models

REGION_ID = "ap-northeast-1"
INSTANCE_ID = "1fe10a3ea4f64a679ea3ee281953ee4a"

_alibaba = load_alibaba()
_config = open_api_models.Config(
    access_key_id=_alibaba["access_key_id"],
    access_key_secret=_alibaba["access_key_secret"],
)
_config.endpoint = f"swas.{REGION_ID}.aliyuncs.com"
client = SwasClient(_config)


def print_header(title: str, instance_id: str | None = None):
    extra = None
    if instance_id:
        extra = f"Instance:  {instance_id[:12]}..."
    _print_header(title, product="SWAS", region=REGION_ID, extra=extra)
    print()


def _instance_ids_json(instance_id: str) -> str:
    return json.dumps([instance_id])


def _default_name(prefix: str) -> str:
    return f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def _fmt_bytes(n: int | float | None) -> str:
    """Human-readable byte size (binary GiB for traffic packages)."""
    if n is None:
        return "-"
    n = float(n)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    i = 0
    while abs(n) >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    if i == 0:
        return f"{int(n)} {units[i]}"
    return f"{n:.2f} {units[i]}"


def _resolve_instance(args) -> str:
    return getattr(args, "instance", None) or INSTANCE_ID


# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------

def list_instances():
    print_header("Instances")
    req = swas_models.ListInstancesRequest(region_id=REGION_ID)
    resp = client.list_instances(req)
    instances = resp.body.instances or []
    for inst in instances:
        spec = inst.resource_spec
        print(f"ID:     {inst.instance_id}")
        print(f"Name:   {inst.instance_name}")
        print(f"Status: {inst.status}")
        print(f"IP:     {inst.public_ip_address} (public) / {inst.inner_ip_address} (private)")
        print(f"Spec:   {spec.cpu} vCPU / {spec.memory} GiB / {spec.disk_size} GiB {spec.disk_category}")
        print(f"Expiry: {inst.expired_time}")
        print("-" * 40)
    return instances


def get_instance(instance_id: str = INSTANCE_ID):
    print_header("Instance Details", instance_id)
    req = swas_models.ListInstancesRequest(
        region_id=REGION_ID,
        instance_ids=_instance_ids_json(instance_id),
    )
    resp = client.list_instances(req)
    instances = resp.body.instances or []
    if not instances:
        print(f"No instance found: {instance_id}")
        return None
    inst = instances[0]
    spec = inst.resource_spec
    image = inst.image
    print(f"ID:           {inst.instance_id}")
    print(f"Name:         {inst.instance_name}")
    print(f"Status:       {inst.status}")
    print(f"Public IP:    {inst.public_ip_address}")
    print(f"Private IP:   {inst.inner_ip_address}")
    print(f"Spec:         {spec.cpu} vCPU / {spec.memory} GiB RAM")
    print(f"Disk:         {spec.disk_size} GiB {spec.disk_category}")
    print(f"Bandwidth:    {spec.bandwidth} Mbps")
    print(f"OS:           {image.image_name} {image.image_version}")
    print(f"Created:      {inst.creation_time}")
    print(f"Expires:      {inst.expired_time}")
    return inst


def start_instance(instance_id: str = INSTANCE_ID):
    print_header("Starting Instance", instance_id)
    req = swas_models.StartInstanceRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.start_instance(req)
    print(f"Start requested: {resp.body}")
    return resp


def stop_instance(instance_id: str = INSTANCE_ID):
    print_header("Stopping Instance", instance_id)
    req = swas_models.StopInstanceRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.stop_instance(req)
    print(f"Stop requested: {resp.body}")
    return resp


def reboot_instance(instance_id: str = INSTANCE_ID):
    print_header("Rebooting Instance", instance_id)
    req = swas_models.RebootInstanceRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.reboot_instance(req)
    print(f"Reboot requested: {resp.body}")
    return resp


def list_traffic_packages(instance_id: str = INSTANCE_ID):
    """Show monthly outbound traffic package usage (egress only; bytes from API)."""
    print_header("Traffic Package", instance_id)
    req = swas_models.ListInstancesTrafficPackagesRequest(
        region_id=REGION_ID,
        instance_ids=_instance_ids_json(instance_id),
    )
    resp = client.list_instances_traffic_packages(req)
    usages = resp.body.instance_traffic_package_usages or []
    if not usages:
        print("No traffic package data (plan may be bandwidth-capped with no GB package).")
        return []

    for u in usages:
        total = u.traffic_package_total or 0
        used = u.traffic_used or 0
        remaining = u.traffic_package_remaining or 0
        overflow = u.traffic_overflow or 0
        pct = (used / total * 100) if total else 0.0
        print(f"Instance:   {u.instance_id}")
        print(f"Total:      {_fmt_bytes(total)}")
        print(f"Used:       {_fmt_bytes(used)}  ({pct:.1f}%)")
        print(f"Remaining:  {_fmt_bytes(remaining)}")
        print(f"Overflow:   {_fmt_bytes(overflow)}")
        if overflow:
            print("Note:       overage billed per GB (Singapore SWAS ≈ ¥0.53/GB)")
        print("-" * 40)
    return usages


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

def list_snapshots(instance_id: str = INSTANCE_ID):
    print_header("Snapshots", instance_id)
    req = swas_models.ListSnapshotsRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.list_snapshots(req)
    snapshots = resp.body.snapshots or []
    if not snapshots:
        print("No snapshots found.")
        return []
    for snap in snapshots:
        print(f"ID:      {snap.snapshot_id}")
        print(f"Name:    {snap.snapshot_name}")
        print(f"Status:  {snap.status}")
        print(f"Created: {snap.creation_time}")
        print(f"Disk ID: {snap.source_disk_id}")
        print("-" * 40)
    return snapshots


def create_snapshot(instance_id: str = INSTANCE_ID, name: str | None = None):
    print_header("Creating Snapshot", instance_id)
    name = name or _default_name("snap")
    req = swas_models.CreateSnapshotRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        snapshot_name=name,
    )
    resp = client.create_snapshot(req)
    print(f"Snapshot created: {resp.body.snapshot_id} ({name})")
    return resp


def delete_snapshot(snapshot_id: str):
    print_header("Deleting Snapshot")
    req = swas_models.DeleteSnapshotRequest(region_id=REGION_ID, snapshot_id=snapshot_id)
    resp = client.delete_snapshot(req)
    print(f"Snapshot deleted: {snapshot_id}")
    return resp


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

def list_images():
    print_header("Available Images")
    req = swas_models.ListImagesRequest(region_id=REGION_ID)
    resp = client.list_images(req)
    images = resp.body.images or []
    for img in images:
        print(f"ID:       {img.image_id}")
        print(f"Name:     {img.image_name}")
        print(f"Type:     {img.image_type}")
        print(f"Platform: {img.platform}")
        print("-" * 40)
    return images


def list_custom_images():
    print_header("Custom Images")
    req = swas_models.ListCustomImagesRequest(region_id=REGION_ID)
    resp = client.list_custom_images(req)
    images = resp.body.custom_images or []
    if not images:
        print("No custom images found.")
        return []
    for img in images:
        print(f"ID:          {img.image_id}")
        print(f"Name:        {img.name}")
        print(f"Status:      {img.status}")
        print(f"Description: {img.description or '-'}")
        print(f"Created:     {img.creation_time}")
        print(f"Region:      {img.region_id}")
        print("-" * 40)
    return images


def create_custom_image(
    instance_id: str | None = None,
    snapshot_id: str | None = None,
    name: str | None = None,
    description: str = "",
):
    print_header("Creating Custom Image")
    name = name or _default_name("image")
    req = swas_models.CreateCustomImageRequest(
        region_id=REGION_ID,
        image_name=name,
        description=description,
    )
    if snapshot_id:
        req.system_snapshot_id = snapshot_id
        print(f"Creating from snapshot: {snapshot_id}")
    else:
        src = instance_id or INSTANCE_ID
        req.instance_id = src
        print(f"Creating from instance: {src[:12]}...")
    resp = client.create_custom_image(req)
    print(f"Custom image created: {resp.body.image_id}")
    return resp


def delete_custom_image(image_id: str):
    print_header("Deleting Custom Image")
    req = swas_models.DeleteCustomImageRequest(region_id=REGION_ID, image_id=image_id)
    resp = client.delete_custom_image(req)
    print(f"Custom image deleted: {image_id}")
    return resp


# ---------------------------------------------------------------------------
# Disks / firewall / run
# ---------------------------------------------------------------------------

def list_disks(instance_id: str = INSTANCE_ID):
    print_header("Disks", instance_id)
    req = swas_models.ListDisksRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.list_disks(req)
    disks = resp.body.disks or []
    for disk in disks:
        print(f"ID:       {disk.disk_id}")
        print(f"Name:     {disk.disk_name}")
        print(f"Size:     {disk.size} GiB")
        print(f"Type:     {disk.disk_type} / {disk.category}")
        print(f"Status:   {disk.status}")
        print("-" * 40)
    return disks


def list_firewall_rules(instance_id: str = INSTANCE_ID):
    print_header("Firewall Rules", instance_id)
    req = swas_models.ListFirewallRulesRequest(region_id=REGION_ID, instance_id=instance_id)
    resp = client.list_firewall_rules(req)
    rules = resp.body.firewall_rules or []
    for rule in rules:
        print(f"Rule ID:  {rule.rule_id}")
        print(f"Port:     {rule.port}")
        print(f"Protocol: {rule.rule_protocol}")
        print(f"Policy:   {rule.policy}")
        print(f"Remark:   {rule.remark or '-'}")
        print("-" * 40)
    return rules


def add_firewall_rule(
    port: str,
    protocol: str = "TCP",
    remark: str = "",
    instance_id: str = INSTANCE_ID,
):
    print_header("Adding Firewall Rule", instance_id)
    req = swas_models.CreateFirewallRuleRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        port=port,
        rule_protocol=protocol,
        remark=remark,
    )
    resp = client.create_firewall_rule(req)
    print(f"Firewall rule added: {port}/{protocol}")
    return resp


def run_command(command: str, instance_id: str = INSTANCE_ID):
    print_header("Running Command", instance_id)
    req = swas_models.RunCommandRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        command_content=command,
        type="RunShellScript",
    )
    resp = client.run_command(req)
    print(f"Command invoked: {resp.body.invoke_id}")
    return resp


# ---------------------------------------------------------------------------
# Command handlers (argparse → functions)
# ---------------------------------------------------------------------------

def cmd_info(args):
    get_instance(_resolve_instance(args))


def cmd_list(_args):
    list_instances()


def cmd_start(args):
    start_instance(_resolve_instance(args))


def cmd_stop(args):
    stop_instance(_resolve_instance(args))


def cmd_reboot(args):
    reboot_instance(_resolve_instance(args))


def cmd_traffic(args):
    list_traffic_packages(_resolve_instance(args))


def cmd_snapshots(args):
    list_snapshots(_resolve_instance(args))


def cmd_snapshot(args):
    iid = _resolve_instance(args)
    if args.action == "create":
        create_snapshot(iid, name=args.name)
    elif args.action == "delete":
        if not args.id:
            raise SystemExit("snapshot delete requires --id")
        delete_snapshot(args.id)
    else:
        list_snapshots(iid)


def cmd_images(_args):
    list_images()


def cmd_image(args):
    if args.action == "create":
        create_custom_image(
            instance_id=_resolve_instance(args) if not args.snapshot_id else None,
            snapshot_id=args.snapshot_id,
            name=args.name,
            description=args.desc or "",
        )
    elif args.action == "delete":
        if not args.id:
            raise SystemExit("image delete requires --id")
        delete_custom_image(args.id)
    else:
        list_custom_images()


def cmd_disks(args):
    list_disks(_resolve_instance(args))


def cmd_firewall(args):
    iid = _resolve_instance(args)
    if args.action == "add":
        if not args.port:
            raise SystemExit("firewall add requires --port")
        add_firewall_rule(args.port, protocol=args.protocol, instance_id=iid)
    else:
        list_firewall_rules(iid)


def cmd_run(args):
    if not args.cmd:
        raise SystemExit("run requires --cmd")
    run_command(args.cmd, _resolve_instance(args))


def _add_instance_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--instance",
        "-i",
        default=INSTANCE_ID,
        help=f"Instance ID (default: {INSTANCE_ID[:12]}...)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SWAS CLI - 轻量应用服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    for name, help_text, handler in (
        ("info", "Show instance details", cmd_info),
        ("list", "List all SWAS instances", cmd_list),
        ("start", "Start instance", cmd_start),
        ("stop", "Stop instance", cmd_stop),
        ("reboot", "Reboot instance", cmd_reboot),
        ("traffic", "Show monthly traffic package usage", cmd_traffic),
        ("snapshots", "List snapshots", cmd_snapshots),
        ("disks", "List disks", cmd_disks),
        ("images", "List marketplace/OS images", cmd_images),
    ):
        p = sub.add_parser(name, help=help_text)
        if name != "list" and name != "images":
            _add_instance_flag(p)
        p.set_defaults(func=handler)

    snap = sub.add_parser("snapshot", help="Create/delete/list snapshots")
    snap.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "create", "delete"],
        help="list (default), create, or delete",
    )
    snap.add_argument("--name", "-n", help="Snapshot name (create)")
    snap.add_argument("--id", help="Snapshot ID (delete)")
    _add_instance_flag(snap)
    snap.set_defaults(func=cmd_snapshot)

    image = sub.add_parser("image", help="Manage custom images")
    image.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "create", "delete"],
        help="list (default), create, or delete",
    )
    image.add_argument("--name", "-n", help="Image name (create)")
    image.add_argument("--id", help="Image ID (delete)")
    image.add_argument("--snapshot-id", help="Create from snapshot instead of instance")
    image.add_argument("--desc", "-d", help="Description (create)")
    _add_instance_flag(image)
    image.set_defaults(func=cmd_image)

    fw = sub.add_parser("firewall", help="List or add firewall rules")
    fw.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list", "add"],
        help="list (default) or add",
    )
    fw.add_argument("--port", "-p", help="Port for add (e.g. 443 or 8000-9000)")
    fw.add_argument("--protocol", default="TCP", help="TCP/UDP/TCP+UDP/ICMP (default: TCP)")
    _add_instance_flag(fw)
    fw.set_defaults(func=cmd_firewall)

    run_p = sub.add_parser("run", help="Run a shell command via Cloud Assistant")
    run_p.add_argument("--cmd", "-c", required=True, help="Shell command to run")
    _add_instance_flag(run_p)
    run_p.set_defaults(func=cmd_run)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
