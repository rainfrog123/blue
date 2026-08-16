#!/usr/bin/env python3
"""Oracle Cloud (OCI) CLI — instances, network discovery, launch presets."""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow `python cli.py` from this directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers
from oci.usage_api.models import Forecast, RequestSummarizedUsagesDetails


def _clients():
    return helpers.get_clients()


def cmd_status(args):
    """Tenancy + region + instances overview."""
    cfg, identity, compute, network = _clients()
    comp = helpers.compartment_id(cfg)
    helpers.print_header("Oracle Cloud Status")

    name = helpers.tenancy_name(identity, cfg["tenancy"])
    print("\n[Account]")
    print(f"  Tenancy: {name}")
    print(f"  Tenancy OCID: {cfg['tenancy']}")
    print(f"  User OCID: {cfg['user']}")
    print(f"  Region: {cfg['region']}")
    print(f"  Fingerprint: {cfg.get('fingerprint', '')}")

    ads = helpers.list_availability_domains(identity, comp)
    print(f"\n[Availability Domains] ({len(ads)})")
    for ad in ads:
        print(f"  {ad.name}")

    instances = helpers.list_instances(compute, comp)
    active = [i for i in instances if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
    print(f"\n[Instances] ({len(active)} active / {len(instances)} total)")
    print("-" * 70)
    if not active:
        print("  No running instances")
    else:
        for inst in active:
            ips = helpers.public_ips_for_instance(compute, network, comp, inst.id)
            shape = inst.shape
            sc = inst.shape_config
            ocpus = getattr(sc, "ocpus", "?") if sc else "?"
            mem = getattr(sc, "memory_in_gbs", "?") if sc else "?"
            ip_s = ", ".join(ips) if ips else "N/A"
            print(f"  {inst.display_name}")
            print(f"    State: {inst.lifecycle_state} | AD: {inst.availability_domain}")
            print(f"    Shape: {shape} | {ocpus} OCPU | {mem} GB")
            print(f"    IP: {ip_s}")
            print(f"    OCID: {inst.id}")
            print()

    subnets = helpers.list_subnets(network, comp)
    print(f"[Subnets] ({len(subnets)})")
    for s in subnets[:10]:
        pub = "public-ok" if not getattr(s, "prohibit_public_ip_on_vnic", False) else "private"
        print(f"  {s.display_name}  {s.cidr_block}  [{pub}]")
    if len(subnets) > 10:
        print(f"  ... +{len(subnets) - 10} more")

    print("=" * 70)


def cmd_account(args):
    cfg, identity, _, _ = _clients()
    name = helpers.tenancy_name(identity, cfg["tenancy"])
    print(f"Tenancy: {name}")
    print(f"Tenancy OCID: {cfg['tenancy']}")
    print(f"User OCID: {cfg['user']}")
    print(f"Region: {cfg['region']}")
    print(f"Fingerprint: {cfg.get('fingerprint', '')}")
    print(f"Key file: {cfg.get('key_file', '')}")


def cmd_list(args):
    cfg, _, compute, network = _clients()
    comp = helpers.compartment_id(cfg)
    instances = helpers.list_instances(compute, comp)
    if args.all:
        rows = instances
    else:
        rows = [i for i in instances if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
    if not rows:
        print("No instances found")
        return
    print(f"{'Name':<24} {'State':<14} {'Shape':<22} {'OCPU':>5} {'GB':>5} {'IP'}")
    print("-" * 100)
    for inst in rows:
        sc = inst.shape_config
        ocpus = getattr(sc, "ocpus", "-") if sc else "-"
        mem = getattr(sc, "memory_in_gbs", "-") if sc else "-"
        ips = helpers.public_ips_for_instance(compute, network, comp, inst.id)
        ip_s = ips[0] if ips else "-"
        print(
            f"{inst.display_name:<24} {inst.lifecycle_state:<14} {inst.shape:<22} "
            f"{ocpus!s:>5} {mem!s:>5} {ip_s}"
        )


def cmd_info(args):
    cfg, _, compute, network = _clients()
    comp = helpers.compartment_id(cfg)
    inst = helpers.resolve_instance(compute, comp, args.id)
    ips = helpers.public_ips_for_instance(compute, network, comp, inst.id)
    sc = inst.shape_config
    print(f"Name: {inst.display_name}")
    print(f"OCID: {inst.id}")
    print(f"State: {inst.lifecycle_state}")
    print(f"AD: {inst.availability_domain}")
    print(f"Shape: {inst.shape}")
    if sc:
        print(f"OCPUs: {sc.ocpus}")
        print(f"Memory GB: {sc.memory_in_gbs}")
    print(f"IPs: {', '.join(ips) if ips else 'N/A'}")
    print(f"Created: {inst.time_created}")
    if ips and not ips[0].startswith("priv:"):
        print(f"\nSSH: ssh ubuntu@{ips[0]}")


def cmd_ads(args):
    cfg, identity, _, _ = _clients()
    ads = helpers.list_availability_domains(identity, helpers.compartment_id(cfg))
    for ad in ads:
        print(ad.name)


def cmd_subnets(args):
    cfg, _, _, network = _clients()
    comp = helpers.compartment_id(cfg)
    for s in helpers.list_subnets(network, comp):
        pub = "public-ok" if not getattr(s, "prohibit_public_ip_on_vnic", False) else "private"
        print(f"{s.display_name}\t{s.cidr_block}\t{pub}\t{s.id}")


def cmd_images(args):
    cfg, _, compute, _ = _clients()
    comp = helpers.compartment_id(cfg)
    shape = args.shape
    if args.preset:
        shape = helpers.PRESETS[args.preset]["shape"]
    img = helpers.latest_ubuntu_image(compute, comp, shape, version=args.version)
    print(f"Shape: {shape}")
    print(f"Image: {img.display_name}")
    print(f"OCID: {img.id}")
    print(f"OS: {img.operating_system} {img.operating_system_version}")


def cmd_presets(args):
    print(f"{'Preset':<12} {'Shape':<22} {'OCPU':>5} {'GB':>5} {'Boot':>5}")
    print("-" * 55)
    for name, p in helpers.PRESETS.items():
        print(
            f"{name:<12} {p['shape']:<22} {p['ocpus']:>5} {p['memory_in_gbs']:>5} {p['boot_gb']:>5}"
        )


def cmd_create(args):
    """Launch instance from preset or explicit shape config."""
    cfg, identity, compute, network = _clients()
    comp = helpers.compartment_id(cfg)

    if args.preset:
        p = helpers.PRESETS[args.preset]
        shape = p["shape"]
        ocpus = p["ocpus"]
        memory = p["memory_in_gbs"]
        boot = args.boot or p["boot_gb"]
        display = args.name or p["display_name"]
    else:
        shape = args.shape
        ocpus = args.ocpus
        memory = args.memory
        boot = args.boot or 50
        display = args.name or "oci-cli-instance"
        if not shape or ocpus is None or memory is None:
            raise SystemExit("Need --preset or --shape + --ocpus + --memory")

    ads = helpers.list_availability_domains(identity, comp)
    if not ads:
        raise SystemExit("No availability domains")
    ad = args.ad or ads[0].name

    subnet = helpers.pick_subnet(network, comp, args.subnet)
    image = helpers.latest_ubuntu_image(compute, comp, shape, version=args.version)
    ssh_pub = helpers.read_ssh_pub(args.ssh_key)

    print(f"Creating: {display}")
    print(f"  Region: {cfg['region']}")
    print(f"  AD: {ad}")
    print(f"  Shape: {shape} | {ocpus} OCPU | {memory} GB | boot {boot} GB")
    print(f"  Subnet: {subnet.display_name} ({subnet.id})")
    print(f"  Image: {image.display_name}")

    launch_kwargs = dict(
        compartment=comp,
        availability_domain=ad,
        shape=shape,
        ocpus=ocpus,
        memory_in_gbs=memory,
        image_id=image.id,
        subnet_id=subnet.id,
        display_name=display,
        ssh_pub=ssh_pub,
        boot_gb=boot,
        assign_public_ip=not args.no_public_ip,
    )

    if args.retry:
        inst = helpers.launch_with_retry(
            compute,
            launch_kwargs,
            retries=args.retry,
            sleep_s=args.retry_sleep,
        )
    else:
        inst = helpers.launch_instance(compute, **launch_kwargs)

    print(f"\nLaunched: {inst.id}")
    print(f"State: {inst.lifecycle_state}")
    if args.wait:
        print("Waiting for RUNNING...")
        inst = helpers.wait_instance_state(compute, inst.id, {"RUNNING"})
        ips = helpers.public_ips_for_instance(compute, network, comp, inst.id)
        print(f"RUNNING | IPs: {', '.join(ips) if ips else 'N/A'}")
        if ips and not ips[0].startswith("priv:"):
            print(f"SSH: ssh ubuntu@{ips[0]}")


def cmd_delete(args):
    cfg, _, compute, _ = _clients()
    comp = helpers.compartment_id(cfg)
    inst = helpers.resolve_instance(compute, comp, args.id)
    if not args.yes:
        print(f"Terminate {inst.display_name} ({inst.id})?")
        if input("Type 'yes' to confirm: ").strip().lower() != "yes":
            print("Cancelled")
            return
    helpers.terminate_instance(compute, inst.id, preserve_boot_volume=args.keep_boot)
    print(f"Terminating {inst.display_name}")


def cmd_power(args):
    cfg, _, compute, _ = _clients()
    comp = helpers.compartment_id(cfg)
    inst = helpers.resolve_instance(compute, comp, args.id)
    action_map = {"on": "START", "off": "STOP", "reboot": "RESET", "softstop": "SOFTSTOP"}
    action = action_map[args.action]
    helpers.instance_action(compute, inst.id, action)
    print(f"{action} -> {inst.display_name}")


def cmd_proxy(args):
    """Run check_proxy.py logic inline."""
    from check_proxy import main as proxy_main

    proxy_main()


def _utc_month_bounds(now: datetime | None = None):
    """Return (month_start, next_month_start, today_start) as naive UTC midnights."""
    now = now or datetime.now(timezone.utc)
    today = datetime(now.year, now.month, now.day)
    month_start = datetime(now.year, now.month, 1)
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1)
    else:
        next_month = datetime(now.year, now.month + 1, 1)
    return month_start, next_month, today


def _fmt_money(amount: float, currency: str) -> str:
    cur = currency or "USD"
    return f"{amount:,.4f} {cur}"


def cmd_cost(args):
    """Month-to-date cost + BASIC forecast to month end (Usage API)."""
    cfg, usage = helpers.usage_client()
    month_start, next_month, today = _utc_month_bounds()
    # Exclusive end for billed MTD (include today if Usage has it).
    usage_end = today + timedelta(days=1)
    # Forecast requires a completed UTC day: usage_ended <= yesterday midnight.
    forecast_anchor = today - timedelta(days=1)
    if forecast_anchor <= month_start:
        forecast_anchor = month_start

    helpers.print_header("Oracle Cloud Cost")
    print(f"\n[Period] {month_start.date()} -> {next_month.date()} (UTC)")
    print(f"  Tenancy: {cfg['tenancy']}")
    print(f"  Region:  {cfg['region']}")

    # MTD by service (no forecast — allows through today)
    mtd = usage.request_summarized_usages(
        RequestSummarizedUsagesDetails(
            tenant_id=cfg["tenancy"],
            time_usage_started=month_start,
            time_usage_ended=usage_end,
            granularity="DAILY",
            query_type="COST",
            group_by=["service"],
        )
    ).data.items or []

    by_svc: dict[str, float] = defaultdict(float)
    currency = "USD"
    for it in mtd:
        amt = float(it.computed_amount or 0)
        by_svc[it.service or "(unspecified)"] += amt
        if it.currency:
            currency = it.currency
    mtd_total = sum(by_svc.values())

    print(f"\n[Month to date] {_fmt_money(mtd_total, currency)}")
    if by_svc:
        for svc, amt in sorted(by_svc.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {svc}: {_fmt_money(amt, currency)}")
    else:
        print("  (no cost rows)")

    # Forecast remainder of month
    forecast_total = 0.0
    try:
        rows = usage.request_summarized_usages(
            RequestSummarizedUsagesDetails(
                tenant_id=cfg["tenancy"],
                time_usage_started=month_start,
                time_usage_ended=forecast_anchor,
                granularity="DAILY",
                query_type="COST",
                group_by=["service"],
                forecast=Forecast(
                    forecast_type="BASIC",
                    time_forecast_started=forecast_anchor,
                    time_forecast_ended=next_month,
                ),
            )
        ).data.items or []
        f_by_svc: dict[str, float] = defaultdict(float)
        for it in rows:
            if not it.is_forecast:
                continue
            amt = float(it.computed_amount or 0)
            f_by_svc[it.service or "(unspecified)"] += amt
            if it.currency:
                currency = it.currency
        forecast_total = sum(f_by_svc.values())
        print(
            f"\n[Forecast] {forecast_anchor.date()} -> {next_month.date()} "
            f"(BASIC) {_fmt_money(forecast_total, currency)}"
        )
        if f_by_svc and (forecast_total > 0 or args.verbose):
            for svc, amt in sorted(f_by_svc.items(), key=lambda x: (-x[1], x[0])):
                if amt == 0 and not args.verbose:
                    continue
                print(f"  {svc}: {_fmt_money(amt, currency)}")
        elif forecast_total == 0:
            print("  (projected $0 - Always Free / no billable burn)")
    except Exception as e:
        print(f"\n[Forecast] unavailable — {e}")

    projected = mtd_total + forecast_total
    print(f"\n[Projected month] {_fmt_money(projected, currency)}")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Oracle Cloud (OCI) CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets:
  a1-free    Always Free Ampere 2 OCPU / 12 GB
  e4-8x64    Trial AMD ~$283/mo
  e4-4x128   Trial AMD RAM-heavy
  a1-32x64   Trial Ampere fat (paid)

Examples:
  python cli.py status
  python cli.py cost
  python cli.py list
  python cli.py create --preset a1-free --wait --retry 100
  python cli.py create --preset e4-8x64 --wait
  python cli.py delete a1-free-tokyo -y
""",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    sub.add_parser("status", help="Comprehensive status")
    sub.add_parser("st", help="Status (alias)")
    sub.add_parser("account", help="Show tenancy / config")

    p_cost = sub.add_parser("cost", help="MTD cost + forecast to month end")
    p_cost.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show $0 forecast service rows",
    )

    p_list = sub.add_parser("list", help="List instances")
    p_list.add_argument("-a", "--all", action="store_true", help="Include terminated")
    sub.add_parser("ls", help="List instances (alias)")

    p_info = sub.add_parser("info", help="Instance details")
    p_info.add_argument("id", help="Display name or OCID")

    sub.add_parser("ads", help="List availability domains")
    sub.add_parser("subnets", help="List subnets")
    sub.add_parser("presets", help="List launch presets")

    p_images = sub.add_parser("images", help="Latest Ubuntu image for a shape")
    p_images.add_argument("--shape", default="VM.Standard.A1.Flex")
    p_images.add_argument("--preset", choices=list(helpers.PRESETS))
    p_images.add_argument("--version", default="22.04")

    p_create = sub.add_parser("create", help="Launch instance")
    p_create.add_argument("-n", "--name", help="Display name")
    p_create.add_argument("--preset", choices=list(helpers.PRESETS), help="Shape preset")
    p_create.add_argument("--shape", help="Shape name (if no preset)")
    p_create.add_argument("--ocpus", type=float)
    p_create.add_argument("--memory", type=float, help="Memory GB")
    p_create.add_argument("--boot", type=int, help="Boot volume GB")
    p_create.add_argument("--ad", help="Availability domain name")
    p_create.add_argument("--subnet", help="Subnet OCID")
    p_create.add_argument("--version", default="22.04", help="Ubuntu version")
    p_create.add_argument("-k", "--ssh-key", help="Path to SSH public key")
    p_create.add_argument("--no-public-ip", action="store_true")
    p_create.add_argument("--wait", action="store_true", help="Wait until RUNNING")
    p_create.add_argument(
        "--retry",
        type=int,
        default=0,
        help="Retry count on capacity errors (0 = once; use large N to poll)",
    )
    p_create.add_argument("--retry-sleep", type=int, default=60, help="Seconds between retries")

    p_delete = sub.add_parser("delete", help="Terminate instance")
    p_delete.add_argument("id", help="Display name or OCID")
    p_delete.add_argument("-y", "--yes", action="store_true")
    p_delete.add_argument("--keep-boot", action="store_true", help="Preserve boot volume")

    p_power = sub.add_parser("power", help="Power control")
    p_power.add_argument("action", choices=["on", "off", "reboot", "softstop"])
    p_power.add_argument("id", help="Display name or OCID")

    sub.add_parser("proxy", help="Check if Python uses system proxy (google.com)")
    sub.add_parser("check-proxy", help="Alias for proxy")

    args = parser.parse_args()

    # aliases that share flags
    if args.command == "ls":
        args.all = False

    dispatch = {
        "status": cmd_status,
        "st": cmd_status,
        "account": cmd_account,
        "cost": cmd_cost,
        "list": cmd_list,
        "ls": cmd_list,
        "info": cmd_info,
        "ads": cmd_ads,
        "subnets": cmd_subnets,
        "presets": cmd_presets,
        "images": cmd_images,
        "create": cmd_create,
        "delete": cmd_delete,
        "power": cmd_power,
        "proxy": cmd_proxy,
        "check-proxy": cmd_proxy,
    }
    fn = dispatch.get(args.command)
    if not fn:
        parser.print_help()
        return
    try:
        fn(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
