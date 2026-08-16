#!/usr/bin/env python3
"""Vultr CLI — account, instances, regions, plans."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers


def cmd_status(args):
    print("=" * 70)
    print("Vultr Status")
    print("=" * 70)

    account = helpers.get_account()
    print("\n[Account]")
    print(f"  Name: {account.get('name', '?')}")
    print(f"  Email: {account.get('email', '?')}")
    print(f"  Org: {account.get('org_name', '?')}")
    bal = account.get("balance")
    pending = account.get("pending_charges")
    print(f"  Balance: {bal}")
    print(f"  Pending charges: {pending}")
    print(f"  Prepayment remaining: {account.get('prepayment_remaining')}")
    print(f"  Last payment: {account.get('last_payment_date')} ({account.get('last_payment_amount')})")
    addr = ", ".join(
        x
        for x in (
            account.get("address1"),
            account.get("city"),
            account.get("postal_code"),
            account.get("country"),
        )
        if x
    )
    if addr:
        print(f"  Address: {addr}")
    acls = account.get("acls") or []
    if acls:
        print(f"  ACLs: {', '.join(acls)}")

    instances = helpers.list_instances()
    print(f"\n[Instances] ({len(instances)} total)")
    print("-" * 70)
    if not instances:
        print("  No instances")
    else:
        for inst in instances:
            ip = helpers.instance_ip(inst)
            print(f"  {inst.get('label') or inst.get('hostname') or inst['id']}")
            print(f"    ID: {inst['id']} | Status: {inst.get('status')} | Power: {inst.get('power_status')}")
            print(f"    Region: {inst.get('region')} | Plan: {inst.get('plan')}")
            print(f"    IP: {ip} | OS: {(inst.get('os') or '?')}")
            print(f"    vCPU: {inst.get('vcpu_count')} | RAM: {inst.get('ram')} MB | Disk: {inst.get('disk')} GB")
            print()

    keys = helpers.list_ssh_keys()
    print(f"[SSH Keys] ({len(keys)})")
    for k in keys[:10]:
        print(f"  {k.get('name')}  {k.get('id')}")
    if len(keys) > 10:
        print(f"  ... +{len(keys) - 10} more")

    print("=" * 70)


def cmd_account(args):
    account = helpers.get_account()
    for k in (
        "name",
        "email",
        "org_name",
        "balance",
        "pending_charges",
        "prepayment_remaining",
        "last_payment_date",
        "last_payment_amount",
        "address1",
        "city",
        "postal_code",
        "country",
    ):
        print(f"{k}: {account.get(k)}")
    acls = account.get("acls") or []
    if acls:
        print(f"acls: {', '.join(acls)}")


def cmd_list(args):
    instances = helpers.list_instances()
    if not instances:
        print("No instances found")
        return
    print(f"{'ID':<38} {'Label':<20} {'Region':<10} {'Plan':<18} {'IP':<16} {'Status'}")
    print("-" * 120)
    for inst in instances:
        label = (inst.get("label") or inst.get("hostname") or "")[:20]
        print(
            f"{inst['id']:<38} {label:<20} {inst.get('region',''):<10} "
            f"{inst.get('plan',''):<18} {helpers.instance_ip(inst):<16} {inst.get('status')}"
        )


def cmd_info(args):
    inst = helpers.get_instance(args.id)
    print(f"ID: {inst['id']}")
    print(f"Label: {inst.get('label')}")
    print(f"Hostname: {inst.get('hostname')}")
    print(f"Status: {inst.get('status')} | Power: {inst.get('power_status')} | Server: {inst.get('server_status')}")
    print(f"Region: {inst.get('region')}")
    print(f"Plan: {inst.get('plan')}")
    print(f"IP: {helpers.instance_ip(inst)}")
    print(f"v6: {inst.get('v6_main_ip')}")
    print(f"OS: {inst.get('os')} ({inst.get('os_id')})")
    print(f"vCPU: {inst.get('vcpu_count')} | RAM: {inst.get('ram')} MB | Disk: {inst.get('disk')} GB")
    print(f"Created: {inst.get('date_created')}")


def cmd_regions(args):
    regions = helpers.list_regions()
    # CN shortlist first if present
    prefer = {"del", "nrt", "osk", "icn", "lax", "sjc", "sgp", "ord"}
    regions = sorted(
        regions,
        key=lambda r: (0 if r.get("id") in prefer else 1, r.get("id") or ""),
    )
    print(f"{'ID':<10} {'City':<22} {'Country':<8} {'Continent'}")
    print("-" * 55)
    for r in regions:
        print(
            f"{r.get('id',''):<10} {r.get('city',''):<22} "
            f"{r.get('country',''):<8} {r.get('continent','')}"
        )


def cmd_plans(args):
    params = {}
    if args.type:
        params["type"] = args.type
    plans = helpers.list_plans(params=params or None)
    plans.sort(key=lambda p: float(p.get("monthly_cost") or 0))
    limit = len(plans) if args.all else min(30, len(plans))
    print(f"{'ID':<28} {'vCPU':>5} {'RAM':>8} {'Disk':>8} {'BW':>8} {'$/mo':>8} {'$/hr':>8}")
    print("-" * 85)
    for p in plans[:limit]:
        ram = p.get("ram") or 0
        print(
            f"{p.get('id',''):<28} {p.get('vcpu_count',0):>5} {ram:>6}MB "
            f"{p.get('disk',0):>6}GB {p.get('bandwidth',0):>6}GB "
            f"{float(p.get('monthly_cost') or 0):>7.2f} {float(p.get('hourly_cost') or 0):>7.4f}"
        )
    if not args.all and len(plans) > limit:
        print(f"\n  ... {len(plans) - limit} more (use --all)")


def cmd_keys(args):
    keys = helpers.list_ssh_keys()
    if not keys:
        print("No SSH keys registered")
        return
    print(f"{'ID':<38} {'Name':<24} {'Date'}")
    print("-" * 80)
    for k in keys:
        print(f"{k.get('id',''):<38} {k.get('name',''):<24} {str(k.get('date_created',''))[:10]}")


def cmd_create(args):
    print(f"Creating instance: {args.label}")
    print(f"  Region: {args.region}")
    print(f"  Plan: {args.plan}")
    print(f"  OS ID: {args.os}")

    payload = {
        "region": args.region,
        "plan": args.plan,
        "os_id": args.os,
        "label": args.label,
        "hostname": args.hostname or args.label,
        "enable_ipv6": True,
    }
    keys = helpers.list_ssh_keys()
    if keys:
        payload["sshkey_id"] = [k["id"] for k in keys]
        print(f"  SSH keys: {len(keys)}")

    inst = helpers.create_instance(**payload)
    print(f"\nCreated ID: {inst['id']}")
    if args.wait:
        print("Waiting for active + IP...")
        inst = helpers.wait_for_instance(inst["id"])
    print(f"IP: {helpers.instance_ip(inst)}")
    print(f"Status: {inst.get('status')}")
    print(f"SSH: ssh root@{helpers.instance_ip(inst)}")


def cmd_delete(args):
    if not args.yes:
        inst = helpers.get_instance(args.id)
        print(f"Delete {inst.get('label')} ({helpers.instance_ip(inst)}) [{args.id}]?")
        if input("Type 'yes' to confirm: ").lower() != "yes":
            print("Cancelled")
            return
    helpers.delete_instance(args.id)
    print(f"Deleted {args.id}")


def main():
    parser = argparse.ArgumentParser(description="Vultr CLI")
    sub = parser.add_subparsers(dest="command", help="Commands")

    sub.add_parser("status", help="Account + instances overview")
    sub.add_parser("st", help="Status (alias)")
    sub.add_parser("account", help="Show account")
    sub.add_parser("list", help="List instances")
    sub.add_parser("ls", help="List instances (alias)")

    p_info = sub.add_parser("info", help="Instance info")
    p_info.add_argument("id", help="Instance UUID")

    sub.add_parser("regions", help="List regions")
    p_plans = sub.add_parser("plans", help="List plans")
    p_plans.add_argument("-a", "--all", action="store_true")
    p_plans.add_argument("-t", "--type", help="Plan type filter (e.g. voc, vhf, vx1)")

    sub.add_parser("keys", help="List SSH keys")

    p_create = sub.add_parser("create", help="Create instance")
    p_create.add_argument("label", help="Label / name")
    p_create.add_argument("-r", "--region", default="nrt", help="Region id (default: nrt Tokyo)")
    p_create.add_argument("-p", "--plan", default="vx1-g-2c-8g", help="Plan id")
    p_create.add_argument(
        "-o",
        "--os",
        type=int,
        default=2284,
        help="OS id (default: 2284 Ubuntu 24.04 x64 — verify with API)",
    )
    p_create.add_argument("--hostname", help="Hostname")
    p_create.add_argument("-w", "--wait", action="store_true", help="Wait for IP")

    p_delete = sub.add_parser("delete", help="Delete instance")
    p_delete.add_argument("id", help="Instance UUID")
    p_delete.add_argument("-y", "--yes", action="store_true")

    args = parser.parse_args()
    try:
        if args.command in ("status", "st"):
            cmd_status(args)
        elif args.command == "account":
            cmd_account(args)
        elif args.command in ("list", "ls"):
            cmd_list(args)
        elif args.command == "info":
            cmd_info(args)
        elif args.command == "regions":
            cmd_regions(args)
        elif args.command == "plans":
            cmd_plans(args)
        elif args.command == "keys":
            cmd_keys(args)
        elif args.command == "create":
            cmd_create(args)
        elif args.command == "delete":
            cmd_delete(args)
        else:
            parser.print_help()
            return 1
    except helpers.VultrAPIError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
