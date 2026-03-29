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
    list_snapshots, create_snapshot, wait_for_snapshot, delete_snapshot, delete_all_snapshots,
    list_disks, get_system_disk,
    create_image_from_snapshot, wait_for_image,
)


# =============================================================================
# NETWORK DISCOVERY
# =============================================================================

def get_network_config():
    """Discover VPC, VSwitch, Security Group, and Key Pair."""
    config = {
        'vpc_id': None,
        'vswitch_id': None,
        'zone_id': 'cn-hongkong-c',
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
                vswitch = next((vs for vs in vswitches if vs.zone_id == "cn-hongkong-c"), vswitches[0])
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
    
    disk = get_system_disk(instance.instance_id)
    if not disk:
        print("[ERROR] No system disk found")
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"Instance: {instance.instance_name} ({instance.instance_id})")
    print(f"Disk: {disk.disk_id} ({disk.size} GB)")
    
    old_snapshots = list_snapshots(verbose=False)
    old_images = list_images("self", verbose=False)
    
    # Step 1: Create snapshot
    print(f"\n[1/5] Creating snapshot...")
    snap_id = create_snapshot(disk.disk_id, f"backup_{timestamp}")
    if not snap_id:
        return None
    
    # Step 2: Wait for snapshot
    print(f"\n[2/5] Waiting for snapshot...")
    if not wait_for_snapshot(snap_id, timeout=1800):
        return None
    
    # Step 3: Create image
    print(f"\n[3/5] Creating image...")
    img_id = create_image_from_snapshot(snap_id, f"backup_{timestamp}")
    if not img_id:
        return None
    
    # Step 4: Wait for image
    print(f"\n[4/5] Waiting for image...")
    if not wait_for_image(img_id, timeout=1800):
        return None
    
    # Step 5: Cleanup old resources
    print(f"\n[5/5] Cleaning up...")
    for img in old_images:
        if img.image_id != img_id:
            delete_image(img.image_id, force=True, verbose=False)
            print(f"  Deleted image: {img.image_id}")
    
    for snap in old_snapshots:
        if snap.snapshot_id != snap_id:
            delete_snapshot(snap.snapshot_id, force=True, verbose=False)
            print(f"  Deleted snapshot: {snap.snapshot_id}")
    
    # Terminate instance
    print(f"\nTerminating instance...")
    terminate_instance(instance.instance_id, force=True)
    
    print(f"\n[OK] Rotate complete")
    print(f"  New snapshot: {snap_id}")
    print(f"  New image: {img_id}")
    return {"snapshot_id": snap_id, "image_id": img_id}


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
        update_vnc_config(public_ip)


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


# =============================================================================
# SSH CONFIG HELPERS
# =============================================================================

def update_ssh_config(new_ip: str, host_alias: str = "ali_hk"):
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


def update_vnc_config(new_ip: str, port: int = 5901):
    """Update RealVNC Viewer saved connection with new IP."""
    import re
    vnc_store = Path.home() / "AppData" / "Roaming" / "RealVNC" / "ViewerStore"
    
    if not vnc_store.exists():
        print(f"[WARN] VNC ViewerStore not found: {vnc_store}")
        return False
    
    try:
        vnc_files = list(vnc_store.glob("*.vnc"))
        if not vnc_files:
            print("[WARN] No saved VNC connections found")
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
        
        return updated > 0
    except Exception as e:
        print(f"[WARN] Failed to update VNC config: {e}")
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
  %(prog)s list instances          List all instances
  %(prog)s list images             List custom images
  %(prog)s provision --spot        Create spot instance from latest image
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
    
    # provision
    prov_parser = subparsers.add_parser('provision', aliases=['prov', 'new'], help='Create new instance')
    prov_parser.add_argument('--image-id', help='Image ID (default: latest custom)')
    prov_parser.add_argument('--type', default='ecs.g7a.xlarge', help='Instance type')
    prov_parser.add_argument('--name', help='Instance name')
    prov_parser.add_argument('--disk-size', type=int, default=63, help='System disk size (GB)')
    prov_parser.add_argument('--spot', action='store_true', help='Use spot instance')
    prov_parser.add_argument('--update-ssh', action='store_true', help='Update SSH config')
    prov_parser.add_argument('--ssh-host', default='ali_hk', help='SSH host alias to update')
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == '__main__':
    main()
