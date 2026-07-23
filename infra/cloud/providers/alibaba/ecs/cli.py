#!/usr/bin/env python3
"""
Alibaba Cloud ECS CLI - Unified command-line interface for ECS management.

Usage:
    python cli.py list instances
    python cli.py list images
    python cli.py provision --spot
    python cli.py terminate
    python cli.py cleanup --images --snapshots
"""
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from aliyun_client import ecs_client, ecs_models, REGION_ID, print_header, create_vpc_client
from ecs_operations import (
    list_instances, get_instance,
    list_images, get_latest_image, create_image, delete_image, delete_all_images,
    list_snapshots, create_snapshot, delete_snapshot, delete_all_snapshots,
    list_disks, get_system_disk,
    wait_for_image,
)


# =============================================================================
# NETWORK DISCOVERY
# =============================================================================

def get_network_config():
    """Discover VPC, VSwitch, Security Group, and Key Pair."""
    config = {
        'vpc_id': None,
        'vswitch_id': None,
        'zone_id': 'ap-southeast-1a',
        'security_group_id': None,
        'key_pair_name': None,
    }
    
    try:
        from alibabacloud_vpc20160428 import models as vpc_models
        vpc_client = create_vpc_client()
        
        # Get VPCs
        vpc_response = vpc_client.describe_vpcs(
            vpc_models.DescribeVpcsRequest(region_id=REGION_ID, page_size=50)
        )
        if vpc_response.body and vpc_response.body.vpcs and vpc_response.body.vpcs.vpc:
            config['vpc_id'] = vpc_response.body.vpcs.vpc[0].vpc_id
            
            # Get VSwitches
            vswitch_response = vpc_client.describe_vswitches(
                vpc_models.DescribeVSwitchesRequest(
                    region_id=REGION_ID,
                    vpc_id=config['vpc_id'],
                    page_size=50
                )
            )
            if vswitch_response.body and vswitch_response.body.v_switches and vswitch_response.body.v_switches.v_switch:
                vswitches = vswitch_response.body.v_switches.v_switch
                preferred = "ap-southeast-1a"
                vswitch = next((vs for vs in vswitches if vs.zone_id == preferred), vswitches[0])
                config['vswitch_id'] = vswitch.v_switch_id
                config['zone_id'] = vswitch.zone_id
    except Exception:
        pass
    
    # Get Security Groups
    try:
        sg_response = ecs_client.describe_security_groups(
            ecs_models.DescribeSecurityGroupsRequest(
                region_id=REGION_ID,
                vpc_id=config['vpc_id'],
                page_size=50
            )
        )
        if sg_response.body and sg_response.body.security_groups and sg_response.body.security_groups.security_group:
            config['security_group_id'] = sg_response.body.security_groups.security_group[0].security_group_id
    except Exception:
        pass
    
    # Get Key Pairs
    try:
        kp_response = ecs_client.describe_key_pairs(
            ecs_models.DescribeKeyPairsRequest(region_id=REGION_ID, page_size=50)
        )
        if kp_response.body and kp_response.body.key_pairs and kp_response.body.key_pairs.key_pair:
            config['key_pair_name'] = kp_response.body.key_pairs.key_pair[0].key_pair_name
    except Exception:
        pass
    
    return config


# =============================================================================
# PROVISION INSTANCE
# =============================================================================

def provision_instance(
    image_id: str = None,
    instance_type: str = "ecs.g7a.xlarge",
    instance_name: str = None,
    disk_size: int = 63,
    spot: bool = False,
):
    """Provision a new ECS instance from an image."""
    print_header("PROVISION INSTANCE")
    
    # Get network config
    net = get_network_config()
    
    if not net['vswitch_id'] or not net['security_group_id']:
        print("[ERROR] Missing network configuration (VSwitch or Security Group)")
        return None, None
    
    # Get image
    if not image_id:
        latest = get_latest_image("self")
        if latest:
            image_id = latest.image_id
            print(f"Using latest image: {latest.image_name} ({image_id})")
        else:
            print("[ERROR] No custom image found. Specify --image-id")
            return None, None
    
    # Generate instance name
    if not instance_name:
        instance_name = f"blue-{datetime.now().strftime('%m%d')}"
    
    print(f"\nProvisioning:")
    print(f"  Image:     {image_id}")
    print(f"  Type:      {instance_type}")
    print(f"  Name:      {instance_name}")
    print(f"  Disk:      {disk_size} GB")
    print(f"  Spot:      {'Yes' if spot else 'No'}")
    print(f"  Zone:      {net['zone_id']}")
    
    try:
        request = ecs_models.RunInstancesRequest(
            region_id=REGION_ID,
            image_id=image_id,
            instance_type=instance_type,
            instance_name=instance_name,
            host_name=instance_name,
            security_group_id=net['security_group_id'],
            v_switch_id=net['vswitch_id'],
            zone_id=net['zone_id'],
            key_pair_name=net['key_pair_name'],
            spot_strategy="SpotAsPriceGo" if spot else "NoSpot",
            system_disk=ecs_models.RunInstancesRequestSystemDisk(
                size=str(disk_size),
                category="cloud_essd",
            ),
            internet_charge_type="PayByTraffic",
            internet_max_bandwidth_out=100,
            instance_charge_type="PostPaid",
            amount=1,
        )
        
        response = ecs_client.run_instances(request)
        instance_ids = response.body.instance_id_sets.instance_id_set
        
        if not instance_ids:
            print("[ERROR] No instance ID returned")
            return None, None
        
        new_id = instance_ids[0]
        print(f"\nInstance created: {new_id}")
        print("Waiting for startup...")
        
        # Wait for running
        for i in range(24):
            time.sleep(5)
            attr = ecs_client.describe_instance_attribute(
                ecs_models.DescribeInstanceAttributeRequest(instance_id=new_id)
            )
            status = attr.body.status
            print(f"  [{i+1}/24] {status}")
            
            if status == "Running":
                pub_ips = attr.body.public_ip_address.ip_address
                pub_ip = pub_ips[0] if pub_ips else None
                print(f"\n[OK] Instance running!")
                print(f"  ID: {new_id}")
                print(f"  IP: {pub_ip}")
                return new_id, pub_ip
        
        return new_id, None
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return None, None


# =============================================================================
# TERMINATE INSTANCE
# =============================================================================

def terminate_instance(instance_id: str = None, force: bool = False):
    """Stop and delete an ECS instance."""
    print_header("TERMINATE INSTANCE")
    
    # Get instance
    if instance_id:
        instance = get_instance(instance_id)
    else:
        instances = list_instances(verbose=False)
        instance = instances[0] if instances else None
    
    if not instance:
        print("No instance found")
        return False
    
    inst_id = instance.instance_id
    print(f"Target: {instance.instance_name} ({inst_id})")
    print(f"Status: {instance.status}")
    
    if not force:
        confirm = input("\nType 'yes' to confirm termination: ")
        if confirm.lower() != 'yes':
            print("Aborted")
            return False
    
    # Stop if running
    if instance.status != "Stopped":
        print("\nStopping instance...")
        ecs_client.stop_instance(
            ecs_models.StopInstanceRequest(instance_id=inst_id, force_stop=True)
        )
        
        for i in range(24):
            time.sleep(5)
            attr = ecs_client.describe_instance_attribute(
                ecs_models.DescribeInstanceAttributeRequest(instance_id=inst_id)
            )
            print(f"  Status: {attr.body.status}")
            if attr.body.status == "Stopped":
                break
    
    # Delete
    print("\nDeleting instance...")
    try:
        ecs_client.delete_instance(
            ecs_models.DeleteInstanceRequest(
                instance_id=inst_id,
                force=True,
                terminate_subscription=True,
            )
        )
        print(f"[OK] Instance {inst_id} deleted")
        return True
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


# =============================================================================
# DIAGNOSE FIREWALL
# =============================================================================

def check_port_in_range(port: int, port_range: str) -> bool:
    """Check if a port is included in a port range string."""
    if not port_range or "/" not in port_range:
        return False
    parts = port_range.split("/")
    if len(parts) != 2:
        return False
    start, end = parts
    if start == "-1" and end == "-1":
        return True
    if start.isdigit() and end.isdigit():
        return int(start) <= port <= int(end)
    return False


def diagnose_firewall(instance_ip: str = None, check_port: int = 443):
    """Analyze security group rules for a specific instance and port."""
    print_header(f"DIAGNOSE FIREWALL - Port {check_port}")
    
    instances = list_instances(verbose=False)
    if not instances:
        print("No instances found")
        return False
    
    # Find target instance
    target = None
    if instance_ip:
        for inst in instances:
            ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
            if ips and ips[0] == instance_ip:
                target = inst
                break
        if not target:
            print(f"No instance found with IP: {instance_ip}")
            return False
    else:
        target = instances[0]
        ips = target.public_ip_address.ip_address if target.public_ip_address else []
        instance_ip = ips[0] if ips else "N/A"
    
    print(f"Instance: {target.instance_name} ({target.instance_id})")
    print(f"IP: {instance_ip}")
    print(f"Port: {check_port}")
    
    port_allowed = False
    for sg_id in target.security_group_ids.security_group_id:
        print(f"\nSecurity Group: {sg_id}")
        
        sg_response = ecs_client.describe_security_group_attribute(
            ecs_models.DescribeSecurityGroupAttributeRequest(
                region_id=REGION_ID, security_group_id=sg_id
            )
        )
        
        if not sg_response.body or not sg_response.body.permissions:
            continue
        
        permissions = sg_response.body.permissions.permission
        ingress = [p for p in permissions if p.direction == "ingress"]
        
        for perm in ingress:
            if check_port_in_range(check_port, perm.port_range):
                status = "ALLOW" if perm.policy == "Accept" else "DENY"
                print(f"  {status}: {perm.ip_protocol.upper()} {perm.port_range} from {perm.source_cidr_ip or 'any'}")
                if perm.policy == "Accept":
                    port_allowed = True
    
    print(f"\nResult: Port {check_port} is {'ALLOWED' if port_allowed else 'BLOCKED'}")
    return port_allowed


# =============================================================================
# ROTATE BACKUP
# =============================================================================

def rotate_and_terminate():
    """Create backup image from instance, delete old backups, then terminate."""
    print_header("ROTATE BACKUP & TERMINATE")
    
    instance = get_instance()
    if not instance:
        print("[ERROR] No instance found")
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"Instance: {instance.instance_name} ({instance.instance_id})")
    
    old_snapshots = list_snapshots(verbose=False)
    old_images = list_images("self", verbose=False)
    
    # Step 1: Create image directly from instance
    print(f"\n[1/3] Creating image from instance...")
    img_id = create_image(instance_id=instance.instance_id, image_name=f"backup_{timestamp}")
    if not img_id:
        return None
    
    # Step 2: Wait for image
    print(f"\n[2/3] Waiting for image...")
    if not wait_for_image(img_id, timeout=1800):
        return None
    
    # Step 3: Cleanup old resources
    print(f"\n[3/3] Cleaning up...")
    for img in old_images:
        if img.image_id != img_id:
            delete_image(img.image_id, force=True, verbose=False)
            print(f"  Deleted image: {img.image_id}")
    
    for snap in old_snapshots:
        delete_snapshot(snap.snapshot_id, force=True, verbose=False)
        print(f"  Deleted snapshot: {snap.snapshot_id}")
    
    # Terminate instance
    print(f"\nTerminating instance...")
    terminate_instance(instance.instance_id, force=True)
    
    print(f"\n[OK] Rotate complete")
    print(f"  New image: {img_id}")
    return {"image_id": img_id}


# =============================================================================
# CLI COMMANDS
# =============================================================================

def cmd_list(args):
    """Handle list subcommand."""
    if args.resource == 'instances':
        list_instances()
    elif args.resource == 'images':
        list_images(args.type)
    elif args.resource == 'snapshots':
        list_snapshots()
    elif args.resource == 'disks':
        list_disks()
    elif args.resource == 'all':
        list_instances()
        list_images("self")
        list_snapshots()
        list_disks()


def cmd_provision(args):
    """Handle provision subcommand."""
    instance_id, public_ip = provision_instance(
        image_id=args.image_id,
        instance_type=args.type,
        instance_name=args.name,
        disk_size=args.disk_size,
        spot=args.spot,
    )
    
    if public_ip and args.update_ssh:
        clear_known_hosts(public_ip)
        update_ssh_config(public_ip, args.ssh_host)
        update_vnc_config(public_ip, name=args.ssh_host)


def cmd_terminate(args):
    """Handle terminate subcommand."""
    terminate_instance(instance_id=args.instance_id, force=args.yes)


def cmd_create(args):
    """Handle create subcommand."""
    if args.resource == 'image':
        if args.instance_id:
            create_image(instance_id=args.instance_id, image_name=args.name)
        elif args.snapshot_id:
            create_image(snapshot_id=args.snapshot_id, image_name=args.name)
        else:
            # Use first instance
            instances = list_instances(verbose=False)
            if instances:
                create_image(instance_id=instances[0].instance_id, image_name=args.name)
            else:
                print("[ERROR] No instance found")
    
    elif args.resource == 'snapshot':
        if args.disk_id:
            create_snapshot(disk_id=args.disk_id, snapshot_name=args.name)
        else:
            # Use first disk
            disks = list_disks(verbose=False)
            if disks:
                create_snapshot(disk_id=disks[0].disk_id, snapshot_name=args.name)
            else:
                print("[ERROR] No disk found")


def cmd_delete(args):
    """Handle delete subcommand."""
    if args.resource == 'image':
        if args.id:
            delete_image(args.id, force=args.force)
        else:
            print("[ERROR] Specify image ID with --id")
    
    elif args.resource == 'snapshot':
        if args.id:
            delete_snapshot(args.id, force=args.force)
        else:
            print("[ERROR] Specify snapshot ID with --id")


def cmd_cleanup(args):
    """Handle cleanup subcommand."""
    print_header("CLEANUP")
    
    if args.images:
        print("\nDeleting all custom images...")
        delete_all_images(keep_ids=args.keep or [], force=True)
    
    if args.snapshots:
        print("\nDeleting all snapshots...")
        delete_all_snapshots(keep_ids=args.keep or [], force=True)
    
    if not args.images and not args.snapshots:
        print("Specify --images and/or --snapshots to clean up")


def cmd_status(args):
    """Handle status subcommand."""
    print_header("STATUS")
    
    instances = list_instances(verbose=False)
    images = list_images("self", verbose=False)
    snapshots = list_snapshots(verbose=False)
    disks = list_disks(verbose=False)
    
    print(f"\nRegion: {REGION_ID}")
    print(f"\nResources:")
    print(f"  Instances:  {len(instances)}")
    print(f"  Images:     {len(images)}")
    print(f"  Snapshots:  {len(snapshots)}")
    print(f"  Disks:      {len(disks)}")
    
    if instances:
        print(f"\nActive Instances:")
        for inst in instances:
            ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
            ip = ips[0] if ips else "N/A"
            print(f"  {inst.instance_name}: {inst.status} ({ip})")


def _bss_client():
    """BSS OpenAPI client (global billing endpoint)."""
    from aliyun_client import ACCESS_KEY_ID, ACCESS_KEY_SECRET, open_api_models
    from alibabacloud_bssopenapi20171214.client import Client as BssClient

    cfg = open_api_models.Config(
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET,
    )
    cfg.endpoint = "business.aliyuncs.com"
    return BssClient(cfg)


# CDT public-traffic free quota (account-wide, since 2025-06-01).
# Docs: https://help.aliyun.com/zh/cdt/internet-data-transfers/
# Only BGP (多线) pay-by-traffic egress; BGP 精品 is excluded.
CDT_FREE_CN_GB = 20.0        # China mainland regions
CDT_FREE_OVERSEAS_GB = 200.0  # non-China (e.g. Singapore)
CDT_FREE_TOTAL_GB = CDT_FREE_CN_GB + CDT_FREE_OVERSEAS_GB  # 220 GB/month

# CDT BGP (多线) list price after free tier — first step (0~10 TB], ¥/GB.
# Full ladder: https://help.aliyun.com/zh/cdt/internet-data-transfers/
CDT_PRICE_CN_YUAN_PER_GB = 0.80       # 中国内地 0~10 TB
CDT_PRICE_APAC_YUAN_PER_GB = 0.70     # 亚太 (Singapore, HK, …) 0~10 TB
CDT_PRICE_EU_NA_YUAN_PER_GB = 0.50    # 欧洲 / 北美 0~10 TB

# IPv6 gateway pay-by-traffic list price when billed on the gateway product
# (not yet rolled into CDT free/ladder on the bill). Singapore = 0.8 ¥/GB.
# Docs: https://help.aliyun.com/zh/ipv6-gateway/product-overview/ipv6-gateway-billing/
# Under CDT, SG IPv6 would use the APAC ladder (0.70 ¥/GB after free) instead.
IPV6_PRICE_SG_YUAN_PER_GB = 0.80


def _cdt_region_bucket(region: str | None) -> str:
    """Map a BSS region label to CDT free-quota bucket: 'cn' or 'overseas'."""
    r = (region or "").strip().lower()
    if not r:
        # Default client region: Singapore → overseas
        return "cn" if REGION_ID.startswith("cn-") else "overseas"
    cn_markers = (
        "中国", "华北", "华东", "华南", "西南", "西北", "华中",
        "cn-", "beijing", "hangzhou", "shanghai", "shenzhen",
        "guangzhou", "chengdu", "qingdao", "zhangjiakou", "huhehaote",
        "wulanchabu", "heyuan", "guangzhou", "nanjing", "fuzhou",
        "wuhan", "xi'an", "zhengzhou", "乌兰察布", "张家口", "呼和浩特",
        "河源", "南京", "福州", "武汉", "西安", "郑州", "成都", "青岛",
        "北京", "杭州", "上海", "深圳", "广州",
    )
    if any(m in r for m in cn_markers):
        return "cn"
    return "overseas"


def _bss_traffic_items(bss, billing_cycle: str, *, billing_date: str | None = None):
    """Return CDT + IPv6 public-traffic billing items for a cycle (or one day)."""
    from alibabacloud_bssopenapi20171214 import models as bss_models

    kwargs = {
        "billing_cycle": billing_cycle,
        "is_billing_item": True,
        "page_size": 100,
        "page_num": 1,
    }
    if billing_date:
        kwargs["billing_date"] = billing_date
        kwargs["granularity"] = "DAILY"

    resp = bss.query_instance_bill(bss_models.QueryInstanceBillRequest(**kwargs))
    items = []
    if resp.body and resp.body.data and resp.body.data.items:
        items = resp.body.data.items.item or []

    traffic = []
    for it in items:
        code = (it.product_code or "").lower()
        detail = it.product_detail or ""
        billing_item = it.billing_item or ""
        if code in ("cdt", "ipv6gateway") or "流量" in billing_item or "流量" in detail:
            traffic.append(it)
    return traffic


def cmd_traffic(args):
    """Show calendar-month public traffic from BSS (CDT IPv4 + IPv6 gateway)."""
    from calendar import monthrange
    from datetime import date

    print_header("TRAFFIC")

    instances = list_instances(verbose=False)
    if instances:
        print("\nInstances:")
        for inst in instances:
            ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
            ip = ips[0] if ips else "N/A"
            charge = getattr(inst, "internet_charge_type", None) or "?"
            bw = getattr(inst, "internet_max_bandwidth_out", None)
            bw_s = f"{bw} Mbps" if bw is not None else "?"
            print(f"  {inst.instance_name} ({inst.instance_id})")
            print(f"    {inst.status} | {ip} | {charge} | max out {bw_s}")
    else:
        print("\nNo ECS instances in this region.")

    today = date.today()
    billing_cycle = args.month or today.strftime("%Y-%m")
    try:
        year, month = map(int, billing_cycle.split("-"))
    except ValueError:
        print(f"\nInvalid --month {billing_cycle!r}; use YYYY-MM")
        return

    print(f"\n{'=' * 50}")
    print("Public traffic — BSS billing (calendar month MTD)")
    print(f"{'=' * 50}")
    print(f"  Period:  {billing_cycle}")
    print("  Source:  CDT (IPv4 fixed public IP) + IPv6 gateway")
    print("  Note:    ECS compute bill lines do not include egress")

    print(f"\n{'=' * 50}")
    print("CDT free quota (account-wide, BGP 多线 only)")
    print(f"{'=' * 50}")
    print(f"  Total:      {CDT_FREE_TOTAL_GB:.0f} GB/month")
    print(f"  China:      {CDT_FREE_CN_GB:.0f} GB/month")
    print(f"  Overseas:   {CDT_FREE_OVERSEAS_GB:.0f} GB/month  (Singapore uses this)")
    print("  Policy:     since 2025-06-01; auto if on CDT billing")

    print(f"\n{'=' * 50}")
    print("List prices (¥/GB, BGP 多线, after free tier)")
    print(f"{'=' * 50}")
    print(f"  CDT China 0~10 TB:     ¥{CDT_PRICE_CN_YUAN_PER_GB:.2f}/GB")
    print(f"  CDT APAC 0~10 TB:      ¥{CDT_PRICE_APAC_YUAN_PER_GB:.2f}/GB  (Singapore)")
    print(f"  CDT EU/NA 0~10 TB:     ¥{CDT_PRICE_EU_NA_YUAN_PER_GB:.2f}/GB")
    print(f"  IPv6 gateway (SG):     ¥{IPV6_PRICE_SG_YUAN_PER_GB:.2f}/GB  (product bill)")
    print(f"  IPv6 via CDT (APAC):   ¥{CDT_PRICE_APAC_YUAN_PER_GB:.2f}/GB  (if billed under CDT)")
    print("  Inside free tier:      ¥0/GB on CDT (list price 0 on bill)")

    try:
        bss = _bss_client()
        month_items = _bss_traffic_items(bss, billing_cycle)
    except Exception as e:
        print(f"\n  Error reading BSS bills: {e}")
        return

    ipv4_gb = ipv6_gb = 0.0
    ipv4_cost = ipv6_cost = 0.0
    cdt_cn_gb = cdt_overseas_gb = 0.0

    if not month_items:
        print("\n  No CDT/IPv6 traffic line items for this month yet.")
    else:
        print()
        for it in month_items:
            usage = float(it.usage or 0)
            amount = float(it.pretax_amount or 0)
            gross = float(getattr(it, "pretax_gross_amount", None) or 0)
            coupons = float(getattr(it, "deducted_by_coupons", None) or 0)
            unit = it.usage_unit or "GB"
            code = (it.product_code or "").lower()
            label = it.billing_item or it.product_detail or code
            price = it.list_price or "?"
            price_unit = it.list_price_unit or ""
            region = getattr(it, "region", None) or ""
            print(f"  {label}")
            print(f"    Product:  {it.product_name} ({it.product_code})")
            if region:
                print(f"    Region:   {region}")
            print(f"    Usage:    {usage:.3f} {unit}")
            print(f"    List:     {price} {price_unit}".rstrip())
            print(f"    Charged:  ¥{amount:.4f}", end="")
            if gross and amount == 0 and coupons:
                print(f"  (gross ¥{gross:.4f}, coupons ¥{coupons:.4f})")
            else:
                print()
            if code == "cdt" or "公网IP" in label:
                ipv4_gb += usage
                ipv4_cost += amount
                if _cdt_region_bucket(region) == "cn":
                    cdt_cn_gb += usage
                else:
                    cdt_overseas_gb += usage
            elif code == "ipv6gateway" or "IPv6" in (it.product_name or ""):
                ipv6_gb += usage
                ipv6_cost += amount

        total_gb = ipv4_gb + ipv6_gb
        total_cost = ipv4_cost + ipv6_cost
        print()
        print(f"  IPv4 (CDT):     {ipv4_gb:.3f} GB   ¥{ipv4_cost:.4f}")
        print(f"  IPv6 gateway:   {ipv6_gb:.3f} GB   ¥{ipv6_cost:.4f}")
        print(f"  Total watched:  {total_gb:.3f} GB   ¥{total_cost:.4f}")

    # Remaining free CDT (IPv4 CDT bill lines only; IPv6 may bill separately)
    cn_left = max(0.0, CDT_FREE_CN_GB - cdt_cn_gb)
    ov_left = max(0.0, CDT_FREE_OVERSEAS_GB - cdt_overseas_gb)
    cn_pct = (cdt_cn_gb / CDT_FREE_CN_GB * 100) if CDT_FREE_CN_GB else 0.0
    ov_pct = (cdt_overseas_gb / CDT_FREE_OVERSEAS_GB * 100) if CDT_FREE_OVERSEAS_GB else 0.0
    print(f"\n{'=' * 50}")
    print("CDT free remaining (vs IPv4 CDT usage)")
    print(f"{'=' * 50}")
    print(f"  China:     {cdt_cn_gb:.3f} / {CDT_FREE_CN_GB:.0f} GB  "
          f"({cn_pct:.1f}%)  left {cn_left:.3f} GB")
    print(f"  Overseas:  {cdt_overseas_gb:.3f} / {CDT_FREE_OVERSEAS_GB:.0f} GB  "
          f"({ov_pct:.1f}%)  left {ov_left:.3f} GB")
    if cdt_overseas_gb > CDT_FREE_OVERSEAS_GB or cdt_cn_gb > CDT_FREE_CN_GB:
        print("  WARNING: over free tier — CDT tiered ¥/GB will apply")
    print("  Note:     IPv6 gateway usage is billed separately (not in these pools)")

    # Implied / projected cost at list prices (Singapore-focused)
    ipv6_list_cost = ipv6_gb * IPV6_PRICE_SG_YUAN_PER_GB
    cdt_over_cn = max(0.0, cdt_cn_gb - CDT_FREE_CN_GB)
    cdt_over_ov = max(0.0, cdt_overseas_gb - CDT_FREE_OVERSEAS_GB)
    cdt_over_cost = (
        cdt_over_cn * CDT_PRICE_CN_YUAN_PER_GB
        + cdt_over_ov * CDT_PRICE_APAC_YUAN_PER_GB
    )
    print(f"\n{'=' * 50}")
    print("Cost at list price (this month)")
    print(f"{'=' * 50}")
    print(f"  CDT over free (CN×{CDT_PRICE_CN_YUAN_PER_GB:.2f} + "
          f"APAC×{CDT_PRICE_APAC_YUAN_PER_GB:.2f}):  ¥{cdt_over_cost:.4f}")
    print(f"  IPv6 @ ¥{IPV6_PRICE_SG_YUAN_PER_GB:.2f}/GB × {ipv6_gb:.3f} GB:  "
          f"¥{ipv6_list_cost:.4f}  (bill may use coupons)")
    print(f"  CDT charged (BSS pretax):     ¥{ipv4_cost:.4f}")
    print(f"  IPv6 charged (BSS pretax):    ¥{ipv6_cost:.4f}")

    # Daily breakdown for days that exist in the month (through today if current month)
    last_day = monthrange(year, month)[1]
    if year == today.year and month == today.month:
        last_day = today.day
    start_day = 1
    if args.days:
        start_day = max(1, last_day - args.days + 1)

    print(f"\nDaily breakdown ({billing_cycle}-{start_day:02d} -> {billing_cycle}-{last_day:02d}):")
    print(f"  {'Date':<12} {'IPv4 GB':>10} {'IPv6 GB':>10} {'Total GB':>10}")
    print(f"  {'-' * 44}")
    month_ipv4 = month_ipv6 = 0.0
    try:
        for day in range(start_day, last_day + 1):
            billing_date = f"{billing_cycle}-{day:02d}"
            day_items = _bss_traffic_items(bss, billing_cycle, billing_date=billing_date)
            d4 = d6 = 0.0
            for it in day_items:
                usage = float(it.usage or 0)
                code = (it.product_code or "").lower()
                if code == "cdt" or "公网IP" in (it.billing_item or ""):
                    d4 += usage
                elif code == "ipv6gateway" or "IPv6" in (it.product_name or ""):
                    d6 += usage
            month_ipv4 += d4
            month_ipv6 += d6
            if d4 or d6 or day == last_day:
                print(f"  {billing_date:<12} {d4:>10.3f} {d6:>10.3f} {d4 + d6:>10.3f}")
        if start_day > 1:
            print(f"  (sum shown window: IPv4 {month_ipv4:.3f} + IPv6 {month_ipv6:.3f} = {month_ipv4 + month_ipv6:.3f} GB)")
    except Exception as e:
        print(f"  Error reading daily bills: {e}")


def cmd_coupon(args):
    """Show account cash balance, cash coupons, and prepaid cards (BSS)."""
    from datetime import date
    from alibabacloud_bssopenapi20171214 import models as bss_models

    print_header("COUPON / BALANCE")

    bss = _bss_client()

    print("\n==================================================")
    print("Account balance")
    print("==================================================")
    try:
        bal = bss.query_account_balance()
        d = bal.body.data if bal.body else None
        if not d:
            print("  (no balance data)")
        else:
            currency = getattr(d, "currency", None) or "CNY"
            print(f"  Available amount:       {getattr(d, 'available_amount', None)} {currency}")
            print(f"  Available cash:         {getattr(d, 'available_cash_amount', None)} {currency}")
            print(f"  Credit amount:          {getattr(d, 'credit_amount', None)} {currency}")
            print(f"  MyBank credit:          {getattr(d, 'mybank_credit_amount', None)} {currency}")
    except Exception as e:
        print(f"  [ERROR] QueryAccountBalance: {e}")

    print("\n==================================================")
    print("Cash coupons" + (" (all returned)" if args.all else " (effective only)"))
    print("==================================================")
    total_balance = 0.0
    try:
        resp = bss.query_cash_coupons(
            bss_models.QueryCashCouponsRequest(
                effective_or_not=False if args.all else True,
            )
        )
        data = resp.body.data if resp.body else None
        coupons = getattr(data, "cash_coupon", None) or [] if data else []
        if not coupons:
            print("  (none)")
        else:
            for c in coupons:
                bal_amt = float(getattr(c, "balance", None) or 0)
                nominal = getattr(c, "nominal_value", None)
                status = getattr(c, "status", None)
                no = getattr(c, "cash_coupon_no", None) or getattr(c, "cash_coupon_id", None)
                desc = (getattr(c, "description", None) or "")[:80]
                products = getattr(c, "applicable_products", None) or ""
                effective = getattr(c, "effective_time", None)
                expiry = getattr(c, "expiry_time", None)
                total_balance += bal_amt
                print(f"  #{no}  [{status}]")
                print(f"    Balance:   ¥{bal_amt:.2f} / ¥{nominal}")
                print(f"    Effective: {effective}  →  Expiry: {expiry}")
                if products:
                    print(f"    Products:  {products}")
                if desc:
                    print(f"    Note:      {desc}")
            print(f"\n  Total coupon balance:  ¥{total_balance:.2f}")
    except Exception as e:
        print(f"  [ERROR] QueryCashCoupons: {e}")

    print("\n==================================================")
    print("Prepaid cards" + (" (all returned)" if args.all else " (effective only)"))
    print("==================================================")
    try:
        resp = bss.query_prepaid_cards(
            bss_models.QueryPrepaidCardsRequest(
                effective_or_not=False if args.all else True,
            )
        )
        data = resp.body.data if resp.body else None
        cards = getattr(data, "prepaid_card", None) or [] if data else []
        if not cards:
            print("  (none)")
        else:
            for c in cards:
                print(
                    f"  {getattr(c, 'prepaid_card_no', None)}  "
                    f"balance ¥{getattr(c, 'balance', None)} / "
                    f"¥{getattr(c, 'denomination', None)}  "
                    f"[{getattr(c, 'status', None)}]  "
                    f"exp {getattr(c, 'expiry_time', None)}"
                )
    except Exception as e:
        print(f"  [ERROR] QueryPrepaidCards: {e}")

    billing_cycle = args.month or date.today().strftime("%Y-%m")
    print("\n==================================================")
    print(f"Coupon deductions on bill ({billing_cycle})")
    print("==================================================")
    try:
        resp = bss.query_account_bill(
            bss_models.QueryAccountBillRequest(
                billing_cycle=billing_cycle,
                is_group_by_product=True,
                page_size=50,
                page_num=1,
            )
        )
        data = resp.body.data if resp.body else None
        items = data.items.item if data and data.items else []
        if not items:
            print("  (no bill lines yet)")
        else:
            coupon_total = 0.0
            cash_total = 0.0
            for it in items:
                name = getattr(it, "product_name", None) or getattr(it, "product_code", None)
                code = getattr(it, "product_code", None)
                coupons = float(getattr(it, "deducted_by_coupons", None) or 0)
                pretax = float(getattr(it, "pretax_amount", None) or 0)
                gross = float(getattr(it, "pretax_gross_amount", None) or 0)
                coupon_total += coupons
                cash_total += pretax
                if coupons or pretax or gross:
                    print(
                        f"  {name} ({code}):  "
                        f"gross ¥{gross:.4f}  coupons ¥{coupons:.4f}  "
                        f"cash ¥{pretax:.4f}"
                    )
            print(f"\n  Month coupon burn:  ¥{coupon_total:.4f}")
            print(f"  Month cash billed:  ¥{cash_total:.4f}")
    except Exception as e:
        print(f"  [ERROR] QueryAccountBill: {e}")


def cmd_diagnose(args):
    """Handle diagnose subcommand."""
    diagnose_firewall(instance_ip=args.ip, check_port=args.port)


def cmd_rotate(args):
    """Handle rotate subcommand."""
    if not args.yes:
        confirm = input("This will backup and TERMINATE the instance. Type 'yes' to confirm: ")
        if confirm.lower() != 'yes':
            print("Aborted")
            return
    rotate_and_terminate()


def _ecs_client_for_region(region_id: str):
    """Build an ECS client for an arbitrary region (default client is REGION_ID)."""
    from aliyun_client import ACCESS_KEY_ID, ACCESS_KEY_SECRET, open_api_models
    from alibabacloud_ecs20140526.client import Client as EcsClient

    cfg = open_api_models.Config(
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET,
    )
    cfg.endpoint = f"ecs.{region_id}.aliyuncs.com"
    return EcsClient(cfg)


def list_spot_prices(
    region_id: str = None,
    max_cpu: int = 4,
    max_mem: float = 8.0,
    top: int = 25,
    disk_size: int = 20,
):
    """Query cheapest SpotAsPriceGo instance types available via API."""
    region_id = region_id or REGION_ID
    client = _ecs_client_for_region(region_id)
    print("=" * 60)
    print(f"ALIBABA CLOUD ECS - SPOT PRICES")
    print("=" * 60)
    print(f"Region:     {region_id}")
    print(f"Filter:     <= {max_cpu} vCPU / {max_mem:g} GiB")
    print(f"Disk:       {disk_size} GB | SpotAsPriceGo | PayByTraffic 1 Mbps")
    print("=" * 60)
    print()

    avail = client.describe_available_resource(
        ecs_models.DescribeAvailableResourceRequest(
            region_id=region_id,
            destination_resource="InstanceType",
            instance_charge_type="PostPaid",
            spot_strategy="SpotAsPriceGo",
        )
    )
    spot_zones = {}
    zones = []
    if avail.body and avail.body.available_zones and avail.body.available_zones.available_zone:
        zones = avail.body.available_zones.available_zone
    for z in zones:
        resources = (
            z.available_resources.available_resource
            if z.available_resources and z.available_resources.available_resource
            else []
        )
        for r in resources:
            supported = (
                r.supported_resources.supported_resource
                if r.supported_resources and r.supported_resources.supported_resource
                else []
            )
            for s in supported:
                if getattr(s, "status", None) == "SoldOut":
                    continue
                if getattr(s, "status_category", None) == "WithoutStock":
                    continue
                spot_zones.setdefault(s.value, set()).add(z.zone_id)

    type_ids = sorted(spot_zones)
    specs = {}
    for i in range(0, len(type_ids), 10):
        batch = type_ids[i : i + 10]
        resp = client.describe_instance_types(
            ecs_models.DescribeInstanceTypesRequest(instance_types=batch)
        )
        types = (
            resp.body.instance_types.instance_type
            if resp.body and resp.body.instance_types
            else []
        )
        for t in types:
            specs[t.instance_type_id] = (t.cpu_core_count, float(t.memory_size))

    candidates = [
        (itype, *specs[itype], sorted(spot_zones[itype])[0])
        for itype in type_ids
        if itype in specs and specs[itype][0] <= max_cpu and specs[itype][1] <= max_mem
    ]

    disk_cats = ("cloud_essd_entry", "cloud_efficiency", "cloud_essd", "cloud_ssd")
    results = []
    for itype, cpu, mem, zone in candidates:
        for disk_cat in disk_cats:
            try:
                sd = ecs_models.DescribePriceRequestSystemDisk(category=disk_cat, size=disk_size)
                price_resp = client.describe_price(
                    ecs_models.DescribePriceRequest(
                        region_id=region_id,
                        resource_type="instance",
                        instance_type=itype,
                        price_unit="Hour",
                        period=1,
                        amount=1,
                        instance_network_type="vpc",
                        internet_charge_type="PayByTraffic",
                        internet_max_bandwidth_out=1,
                        system_disk=sd,
                        spot_strategy="SpotAsPriceGo",
                    )
                )
                pi = price_resp.body.price_info.price
                results.append(
                    {
                        "type": itype,
                        "cpu": cpu,
                        "mem": mem,
                        "zone": zone,
                        "disk": disk_cat,
                        "price": float(pi.trade_price),
                        "currency": pi.currency,
                    }
                )
                break
            except Exception:
                continue

    results.sort(key=lambda r: r["price"])
    print(f"Spot-available types: {len(spot_zones)} | Priced (filtered): {len(results)}\n")
    print(f"{'Price/h':>12}  {'~/mo':>8}  {'Type':28s} {'Spec':10s} {'Disk':18s} Zone")
    print("-" * 100)
    for r in results[:top]:
        monthly = r["price"] * 720
        print(
            f"{r['price']:12.6f}  {monthly:8.2f}  {r['type']:28s} "
            f"{r['cpu']}C/{r['mem']:g}G{'':3s} {r['disk']:18s} {r['zone']}"
        )

    if results:
        best = results[0]
        usable = next((r for r in results if r["mem"] >= 2.0), None)
        print(f"\nCheapest overall: {best['type']} ({best['cpu']}C/{best['mem']:g}G) "
              f"@ {best['price']:.6f} {best['currency']}/h "
              f"(~{best['price'] * 720:.2f}/mo if always up)")
        if usable:
            print(f"Cheapest >=2 GiB:  {usable['type']} ({usable['cpu']}C/{usable['mem']:g}G) "
                  f"@ {usable['price']:.6f} {usable['currency']}/h "
                  f"(~{usable['price'] * 720:.2f}/mo if always up)")
        print("Note: prices include 20 GB system disk + 1 Mbps pay-by-traffic; spot can be reclaimed.")
    else:
        print("No priced spot candidates matched the filter.")
    return results


def cmd_spot_prices(args):
    """Handle spot-prices subcommand."""
    list_spot_prices(
        region_id=args.region,
        max_cpu=args.max_cpu,
        max_mem=args.max_mem,
        top=args.top,
        disk_size=args.disk_size,
    )


# =============================================================================
# SSH CONFIG HELPERS
# =============================================================================

def update_ssh_config(new_ip: str, host_alias: str = "ali_sg"):
    """Update SSH config with new IP."""
    import re
    ssh_config = Path.home() / ".ssh" / "config"
    
    if not ssh_config.exists():
        print(f"[WARN] SSH config not found: {ssh_config}")
        return
    
    try:
        content = ssh_config.read_text(encoding='utf-8')
        pattern = rf'(Host\s+{re.escape(host_alias)}\s*\n\s*HostName\s+)\S+'
        
        if re.search(pattern, content):
            new_content = re.sub(pattern, rf'\g<1>{new_ip}', content)
            ssh_config.write_text(new_content, encoding='utf-8')
            print(f"[OK] SSH config updated: {host_alias} -> {new_ip}")
        else:
            print(f"[WARN] Host '{host_alias}' not found in SSH config")
    except Exception as e:
        print(f"[WARN] Failed to update SSH config: {e}")


def clear_known_hosts(ip: str):
    """Clear SSH known_hosts entries for IP."""
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    
    if not known_hosts.exists():
        return
    
    try:
        content = known_hosts.read_text(encoding='utf-8')
        lines = content.splitlines()
        filtered = [l for l in lines if not l.startswith(ip) and not l.startswith(f"[{ip}]")]
        
        if len(filtered) < len(lines):
            known_hosts.write_text('\n'.join(filtered) + '\n', encoding='utf-8')
            print(f"[OK] Cleared known_hosts entries for {ip}")
    except Exception:
        pass


VNC_PASSWORD = "Xk9#mP2$vNc@2026"
VNC_USERNAME = "vncuser"


def update_vnc_config(new_ip: str, port: int = 5901, name: str = "ali_sg"):
    """Create/update VNC connection for Remmina (Linux) or RealVNC (Windows)."""
    import re
    import base64
    
    # Try Remmina (Linux)
    remmina_dir = Path.home() / ".local" / "share" / "remmina"
    if remmina_dir.exists() or not (Path.home() / "AppData").exists():
        remmina_dir.mkdir(parents=True, exist_ok=True)
        remmina_file = remmina_dir / f"{name}.remmina"
        
        # Remmina uses base64 for password (not secure, but that's how it works)
        encoded_pass = base64.b64encode(VNC_PASSWORD.encode()).decode()
        
        content = f"""[remmina]
name={name}
group=
server={new_ip}:{port}
protocol=VNC
username={VNC_USERNAME}
password={encoded_pass}
colordepth=24
quality=2
viewmode=1
window_maximize=1
"""
        remmina_file.write_text(content, encoding='utf-8')
        print(f"[OK] Remmina connection created: {remmina_file}")
        print(f"     VNC: {new_ip}:{port}")
        print(f"     User: {VNC_USERNAME}")
        print(f"     Pass: {VNC_PASSWORD}")
        return True
    
    # Try RealVNC (Windows)
    vnc_store = Path.home() / "AppData" / "Roaming" / "RealVNC" / "ViewerStore"
    if vnc_store.exists():
        try:
            vnc_files = list(vnc_store.glob("*.vnc"))
            if not vnc_files:
                print("[WARN] No saved VNC connections found")
                print(f"[INFO] Connect manually: {new_ip}:{port}")
                print(f"       User: {VNC_USERNAME}, Pass: {VNC_PASSWORD}")
                return False
            
            updated = 0
            for vnc_file in vnc_files:
                content = vnc_file.read_text(encoding='utf-8')
                if "Host=" in content:
                    new_content = re.sub(r'Host=[\d\.]+:\d+', f'Host={new_ip}:{port}', content)
                    if new_content != content:
                        vnc_file.write_text(new_content, encoding='utf-8')
                        print(f"[OK] VNC updated: {vnc_file.name} -> {new_ip}:{port}")
                        updated += 1
            
            if updated:
                print(f"     User: {VNC_USERNAME}, Pass: {VNC_PASSWORD}")
            return updated > 0
        except Exception as e:
            print(f"[WARN] Failed to update VNC config: {e}")
    
    # Fallback: just print connection info
    print(f"[INFO] VNC connection details:")
    print(f"       Address: {new_ip}:{port}")
    print(f"       User: {VNC_USERNAME}")
    print(f"       Pass: {VNC_PASSWORD}")
    return False


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Alibaba Cloud ECS CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                  Show resource summary
  %(prog)s traffic                 Public egress this month (CDT + IPv6)
  %(prog)s coupon                  Cash coupons + balance + month burn
  %(prog)s list instances          List all instances
  %(prog)s list images             List custom images
  %(prog)s provision --spot        Create spot instance from latest image
  %(prog)s spot-prices             Cheapest Singapore spot types (API)
  %(prog)s terminate               Stop and delete instance
  %(prog)s create image            Create image from current instance
  %(prog)s cleanup --images        Delete all custom images
  %(prog)s diagnose --port 22      Check if port 22 is open
  %(prog)s rotate                  Backup to image and terminate instance
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # list
    list_parser = subparsers.add_parser('list', aliases=['ls'], help='List resources')
    list_parser.add_argument('resource', choices=['instances', 'images', 'snapshots', 'disks', 'all'],
                             help='Resource type to list')
    list_parser.add_argument('--type', default='self', help='Image type (self/system/others)')
    list_parser.set_defaults(func=cmd_list)
    
    # status
    status_parser = subparsers.add_parser('status', aliases=['st'], help='Show status summary')
    status_parser.set_defaults(func=cmd_status)

    # traffic
    traffic_parser = subparsers.add_parser(
        'traffic', aliases=['bw', 'egress'],
        help='Show public traffic this month (BSS CDT IPv4 + IPv6 gateway)',
    )
    traffic_parser.add_argument(
        '--month', default=None,
        help='Billing month YYYY-MM (default: current calendar month)',
    )
    traffic_parser.add_argument(
        '--days', type=int, default=None,
        help='Only show the last N days in the daily breakdown',
    )
    traffic_parser.set_defaults(func=cmd_traffic)

    # coupon / balance
    coupon_parser = subparsers.add_parser(
        'coupon', aliases=['coupons', 'balance', 'bss'],
        help='Show cash balance, cash coupons, prepaid cards, month coupon burn',
    )
    coupon_parser.add_argument(
        '--all', action='store_true',
        help='Include non-effective / expired coupons & cards if API returns them',
    )
    coupon_parser.add_argument(
        '--month', default=None,
        help='Billing month YYYY-MM for coupon burn (default: current month)',
    )
    coupon_parser.set_defaults(func=cmd_coupon)
    
    # provision
    prov_parser = subparsers.add_parser('provision', aliases=['prov', 'new'], help='Create new instance')
    prov_parser.add_argument('--image-id', help='Image ID (default: latest custom)')
    prov_parser.add_argument('--type', default='ecs.g7a.xlarge', help='Instance type')
    prov_parser.add_argument('--name', help='Instance name')
    prov_parser.add_argument('--disk-size', type=int, default=63, help='System disk size (GB)')
    prov_parser.add_argument('--spot', action='store_true', help='Use spot instance')
    prov_parser.add_argument('--update-ssh', action='store_true', help='Update SSH config')
    prov_parser.add_argument('--ssh-host', default='ali_sg', help='SSH host alias to update')
    prov_parser.set_defaults(func=cmd_provision)
    
    # terminate
    term_parser = subparsers.add_parser('terminate', aliases=['term', 'rm'], help='Terminate instance')
    term_parser.add_argument('--instance-id', help='Instance ID (default: first instance)')
    term_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    term_parser.set_defaults(func=cmd_terminate)
    
    # create
    create_parser = subparsers.add_parser('create', help='Create image or snapshot')
    create_parser.add_argument('resource', choices=['image', 'snapshot'], help='Resource to create')
    create_parser.add_argument('--name', help='Resource name')
    create_parser.add_argument('--instance-id', help='Instance ID (for image)')
    create_parser.add_argument('--snapshot-id', help='Snapshot ID (for image from snapshot)')
    create_parser.add_argument('--disk-id', help='Disk ID (for snapshot)')
    create_parser.set_defaults(func=cmd_create)
    
    # delete
    del_parser = subparsers.add_parser('delete', aliases=['del'], help='Delete image or snapshot')
    del_parser.add_argument('resource', choices=['image', 'snapshot'], help='Resource to delete')
    del_parser.add_argument('--id', required=True, help='Resource ID')
    del_parser.add_argument('--force', action='store_true', help='Force delete')
    del_parser.set_defaults(func=cmd_delete)
    
    # cleanup
    clean_parser = subparsers.add_parser('cleanup', aliases=['clean'], help='Bulk delete resources')
    clean_parser.add_argument('--images', action='store_true', help='Delete all images')
    clean_parser.add_argument('--snapshots', action='store_true', help='Delete all snapshots')
    clean_parser.add_argument('--keep', nargs='+', help='IDs to keep')
    clean_parser.set_defaults(func=cmd_cleanup)
    
    # diagnose
    diag_parser = subparsers.add_parser('diagnose', aliases=['diag', 'fw'], help='Diagnose firewall/security group')
    diag_parser.add_argument('--ip', help='Instance IP (default: first instance)')
    diag_parser.add_argument('--port', type=int, default=443, help='Port to check (default: 443)')
    diag_parser.set_defaults(func=cmd_diagnose)
    
    # rotate
    rotate_parser = subparsers.add_parser('rotate', help='Backup instance to image, then terminate')
    rotate_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    rotate_parser.set_defaults(func=cmd_rotate)

    # spot-prices
    spot_parser = subparsers.add_parser(
        'spot-prices', aliases=['spot', 'prices'],
        help='List cheapest Spot instance types via DescribePrice',
    )
    spot_parser.add_argument('--region', default=REGION_ID, help='Region (default: Singapore)')
    spot_parser.add_argument('--max-cpu', type=int, default=4, help='Max vCPU filter')
    spot_parser.add_argument('--max-mem', type=float, default=8.0, help='Max memory GiB filter')
    spot_parser.add_argument('--top', type=int, default=25, help='Rows to print')
    spot_parser.add_argument('--disk-size', type=int, default=20, help='System disk GB for pricing')
    spot_parser.set_defaults(func=cmd_spot_prices)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == '__main__':
    main()
