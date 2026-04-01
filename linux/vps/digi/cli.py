#!/usr/bin/env python3
"""DigitalOcean CLI for droplet management."""

import argparse
import sys

import helpers


def cmd_status(args):
    """Comprehensive status check - account, droplets, and billing."""
    print("=" * 70)
    print("DigitalOcean Status")
    print("=" * 70)
    
    # Account info
    account = helpers.get_account()
    print(f"\n[Account]")
    print(f"  Email: {account['email']}")
    print(f"  Status: {account['status']}")
    print(f"  Droplet Limit: {account['droplet_limit']}")
    
    # Balance
    balance = helpers.get_balance()
    print(f"\n[Billing]")
    print(f"  Month-to-date Usage: ${balance['month_to_date_usage']}")
    print(f"  Account Balance: ${balance['account_balance']}")
    
    # Droplets with pricing
    droplets = helpers.list_droplets()
    sizes = helpers.list_sizes(available_only=False)
    size_map = {s['slug']: s for s in sizes}
    
    print(f"\n[Droplets] ({len(droplets)} active)")
    print("-" * 70)
    
    if droplets:
        total_monthly = 0
        for d in droplets:
            ip = helpers.get_droplet_ip(d) or "N/A"
            size_info = size_map.get(d['size_slug'], {})
            price = size_info.get('price_monthly', 0)
            total_monthly += price
            vcpus = size_info.get('vcpus', d.get('vcpus', '?'))
            memory_gb = size_info.get('memory', d.get('memory', 0)) / 1024
            disk = size_info.get('disk', d.get('disk', '?'))
            
            print(f"  {d['name']}")
            print(f"    IP: {ip} | Region: {d['region']['slug']} | Status: {d['status']}")
            print(f"    Size: {d['size_slug']}")
            print(f"    Specs: {vcpus} vCPU | {memory_gb:.0f}GB RAM | {disk}GB disk")
            print(f"    Cost: ${price}/month (${size_info.get('price_hourly', 0)}/hour)")
            print()
        
        print(f"  Total Monthly Cost: ${total_monthly}/month")
    else:
        print("  No droplets running")
    
    print("=" * 70)


def cmd_account(args):
    """Show account info."""
    account = helpers.get_account()
    print(f"Email: {account['email']}")
    print(f"Status: {account['status']}")
    print(f"Droplet Limit: {account['droplet_limit']}")
    print(f"Floating IP Limit: {account.get('floating_ip_limit', 'N/A')}")
    print(f"Email Verified: {account['email_verified']}")
    print(f"UUID: {account['uuid']}")


def cmd_balance(args):
    """Show account balance and billing info."""
    balance = helpers.get_balance()
    print(f"Month-to-date Usage: ${balance['month_to_date_usage']}")
    print(f"Account Balance: ${balance['account_balance']}")
    print(f"Generated At: {balance['generated_at']}")


def cmd_list(args):
    """List all droplets."""
    droplets = helpers.list_droplets()
    if not droplets:
        print("No droplets found")
        return
    
    print(f"{'ID':<12} {'Name':<20} {'Region':<8} {'Size':<22} {'IP':<16} {'Status'}")
    print("-" * 90)
    for d in droplets:
        ip = helpers.get_droplet_ip(d) or "N/A"
        print(f"{d['id']:<12} {d['name']:<20} {d['region']['slug']:<8} {d['size_slug']:<22} {ip:<16} {d['status']}")


def cmd_create(args):
    """Create a new droplet."""
    print(f"Creating droplet: {args.name}")
    print(f"  Region: {args.region}")
    print(f"  Size: {args.size}")
    print(f"  Image: {args.image}")
    
    # Handle SSH keys - use all registered keys by default
    ssh_key_ids = []
    if args.ssh_key:
        print(f"  SSH Key: registering...")
        key = helpers.find_or_create_ssh_key("cli-key", args.ssh_key)
        ssh_key_ids.append(key["id"])
        print(f"  SSH Key ID: {key['id']} ({key['name']})")
    else:
        # Use all registered SSH keys
        keys = helpers.list_ssh_keys()
        if keys:
            ssh_key_ids = [k["id"] for k in keys]
            print(f"  SSH Keys: {len(ssh_key_ids)} keys ({', '.join(k['name'] for k in keys)})")
    
    # Create droplet
    droplet = helpers.create_droplet(
        name=args.name,
        region=args.region,
        size=args.size,
        image=args.image,
        ssh_keys=ssh_key_ids if ssh_key_ids else None,
        ipv6=True,
        monitoring=True,
    )
    
    print(f"\nDroplet created! ID: {droplet['id']}")
    print("Waiting for droplet to become active...")
    
    droplet = helpers.wait_for_droplet(droplet["id"])
    ip = helpers.get_droplet_ip(droplet)
    
    print(f"\n{'='*50}")
    print(f"Droplet ready!")
    print(f"  ID: {droplet['id']}")
    print(f"  Name: {droplet['name']}")
    print(f"  IP: {ip}")
    print(f"  Region: {droplet['region']['slug']}")
    print(f"  Size: {droplet['size_slug']}")
    print(f"\nSSH: ssh root@{ip}")
    print(f"{'='*50}")


def cmd_delete(args):
    """Delete a droplet."""
    droplet_id = args.id
    
    # Confirm
    if not args.yes:
        droplet = helpers.get_droplet(droplet_id)
        ip = helpers.get_droplet_ip(droplet) or "N/A"
        print(f"Delete droplet {droplet['name']} ({ip})?")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != "yes":
            print("Cancelled")
            return
    
    helpers.delete_droplet(droplet_id)
    print(f"Droplet {droplet_id} deleted")


def cmd_info(args):
    """Show droplet info."""
    droplet = helpers.get_droplet(args.id)
    ip = helpers.get_droplet_ip(droplet)
    
    print(f"ID: {droplet['id']}")
    print(f"Name: {droplet['name']}")
    print(f"Status: {droplet['status']}")
    print(f"IP: {ip}")
    print(f"Region: {droplet['region']['slug']} ({droplet['region']['name']})")
    print(f"Size: {droplet['size_slug']}")
    print(f"vCPUs: {droplet['vcpus']}")
    print(f"Memory: {droplet['memory']} MB")
    print(f"Disk: {droplet['disk']} GB")
    print(f"Image: {droplet['image']['slug']}")
    print(f"Created: {droplet['created_at']}")


def cmd_power(args):
    """Power on/off or reboot droplet."""
    action = args.action
    droplet_id = args.id
    
    if action == "on":
        helpers.power_on(droplet_id)
        print(f"Powering on droplet {droplet_id}")
    elif action == "off":
        helpers.power_off(droplet_id)
        print(f"Powering off droplet {droplet_id}")
    elif action == "reboot":
        helpers.reboot(droplet_id)
        print(f"Rebooting droplet {droplet_id}")


def cmd_regions(args):
    """List available regions."""
    regions = helpers.list_regions()
    print(f"{'Slug':<10} {'Name':<25}")
    print("-" * 35)
    for r in regions:
        print(f"{r['slug']:<10} {r['name']:<25}")


def cmd_sizes(args):
    """List available sizes."""
    sizes = helpers.list_sizes()
    
    # Sort by price
    sizes.sort(key=lambda x: x['price_monthly'], reverse=args.desc)
    
    print(f"{'Slug':<35} {'vCPU':>5} {'RAM':>8} {'Disk':>8} {'Transfer':>10} {'Price':>10}")
    print("-" * 85)
    
    limit = args.all and len(sizes) or 20
    for s in sizes[:limit]:
        ram_gb = s['memory'] / 1024
        print(f"{s['slug']:<35} {s['vcpus']:>5} {ram_gb:>6.0f}GB {s['disk']:>6}GB {s['transfer']:>8.0f}TB  ${s['price_monthly']:>6}/mo")
    
    if not args.all and len(sizes) > 20:
        print(f"\n  ... {len(sizes) - 20} more sizes (use --all to show all)")


def cmd_keys(args):
    """List SSH keys."""
    keys = helpers.list_ssh_keys()
    if not keys:
        print("No SSH keys registered")
        return
    print(f"{'ID':<12} {'Name':<20} {'Fingerprint'}")
    print("-" * 70)
    for k in keys:
        print(f"{k['id']:<12} {k['name']:<20} {k['fingerprint']}")


def cmd_snapshots(args):
    """List snapshots."""
    snapshots = helpers.list_snapshots()
    if not snapshots:
        print("No snapshots found")
        return
    print(f"{'ID':<12} {'Name':<25} {'Size':<10} {'Region':<10} {'Created'}")
    print("-" * 80)
    for s in snapshots:
        size_gb = s["size_gigabytes"]
        regions = ",".join(s["regions"][:2])
        created = s["created_at"][:10]
        print(f"{s['id']:<12} {s['name']:<25} {size_gb}GB{'':<6} {regions:<10} {created}")


def cmd_save(args):
    """Snapshot droplet and delete it (saves cost)."""
    droplet_id = args.id
    droplet = helpers.get_droplet(droplet_id)
    ip = helpers.get_droplet_ip(droplet) or "N/A"
    
    snapshot_name = args.name or f"{droplet['name']}-snap"
    
    if not args.yes:
        print(f"This will:")
        print(f"  1. Snapshot droplet {droplet['name']} ({ip})")
        print(f"  2. DELETE the droplet (stops billing)")
        print(f"\nSnapshot name: {snapshot_name}")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != "yes":
            print("Cancelled")
            return
    
    snapshot = helpers.snapshot_and_delete(droplet_id, snapshot_name)
    
    print(f"\n{'='*50}")
    print(f"Done! Droplet saved and deleted.")
    print(f"  Snapshot ID: {snapshot['id']}")
    print(f"  Snapshot Name: {snapshot['name']}")
    print(f"  Size: {snapshot['size_gigabytes']}GB (~${snapshot['size_gigabytes'] * 0.06:.2f}/mo)")
    print(f"\nTo restore: python cli.py restore {snapshot['id']} <name>")
    print(f"{'='*50}")


def cmd_restore(args):
    """Restore droplet from snapshot."""
    snapshot_id = args.snapshot_id
    name = args.name
    
    snapshot = helpers.get_snapshot(snapshot_id)
    print(f"Restoring from snapshot: {snapshot['name']}")
    print(f"  New droplet name: {name}")
    print(f"  Region: {args.region}")
    print(f"  Size: {args.size}")
    
    # Get SSH key
    ssh_keys = None
    keys = helpers.list_ssh_keys()
    if keys:
        ssh_keys = [k["id"] for k in keys]
        print(f"  SSH Keys: {len(ssh_keys)} keys")
    
    droplet = helpers.restore_from_snapshot(
        snapshot_id=snapshot_id,
        name=name,
        region=args.region,
        size=args.size,
        ssh_keys=ssh_keys,
    )
    
    print(f"\nDroplet created! ID: {droplet['id']}")
    print("Waiting for droplet to become active...")
    
    droplet = helpers.wait_for_droplet(droplet["id"])
    ip = helpers.get_droplet_ip(droplet)
    
    print(f"\n{'='*50}")
    print(f"Droplet restored!")
    print(f"  ID: {droplet['id']}")
    print(f"  Name: {droplet['name']}")
    print(f"  IP: {ip}")
    print(f"\nSSH: ssh root@{ip}")
    print(f"{'='*50}")


# --- Reserved IP Commands ---

def cmd_ips(args):
    """List reserved IPs."""
    ips = helpers.list_reserved_ips()
    if not ips:
        print("No reserved IPs found")
        return
    
    print(f"{'IP Address':<18} {'Region':<8} {'Droplet':<25} {'Droplet ID'}")
    print("-" * 70)
    for ip in ips:
        addr = ip["ip"]
        region = ip["region"]["slug"]
        droplet = ip.get("droplet")
        if droplet:
            droplet_name = droplet.get("name", "unknown")
            droplet_id = droplet["id"]
        else:
            droplet_name = "(unassigned)"
            droplet_id = "-"
        print(f"{addr:<18} {region:<8} {droplet_name:<25} {droplet_id}")


def cmd_ip_create(args):
    """Create a reserved IP."""
    if args.droplet:
        print(f"Creating reserved IP for droplet {args.droplet}...")
        ip = helpers.create_reserved_ip(droplet_id=args.droplet)
    else:
        print(f"Creating reserved IP in region {args.region}...")
        ip = helpers.create_reserved_ip(region=args.region)
    
    print(f"\n{'='*50}")
    print(f"Reserved IP created!")
    print(f"  IP: {ip['ip']}")
    print(f"  Region: {ip['region']['slug']}")
    if ip.get("droplet"):
        print(f"  Assigned to: {ip['droplet']['name']} (ID: {ip['droplet']['id']})")
    print(f"\nCost: $5/month (free if assigned to a droplet)")
    print(f"{'='*50}")


def cmd_ip_assign(args):
    """Assign reserved IP to droplet."""
    print(f"Assigning {args.ip} to droplet {args.droplet_id}...")
    helpers.assign_reserved_ip(args.ip, args.droplet_id)
    print(f"Reserved IP {args.ip} assigned to droplet {args.droplet_id}")


def cmd_ip_unassign(args):
    """Unassign reserved IP from droplet."""
    print(f"Unassigning {args.ip}...")
    helpers.unassign_reserved_ip(args.ip)
    print(f"Reserved IP {args.ip} unassigned")


def cmd_ip_delete(args):
    """Delete a reserved IP."""
    if not args.yes:
        print(f"Delete reserved IP {args.ip}?")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != "yes":
            print("Cancelled")
            return
    
    helpers.delete_reserved_ip(args.ip)
    print(f"Reserved IP {args.ip} deleted")


def main():
    parser = argparse.ArgumentParser(description="DigitalOcean CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # status (comprehensive check)
    subparsers.add_parser("status", help="Comprehensive status check")
    subparsers.add_parser("st", help="Status (alias)")
    
    # account
    subparsers.add_parser("account", help="Show account info")
    
    # balance
    subparsers.add_parser("balance", help="Show billing/balance info")
    subparsers.add_parser("billing", help="Show billing/balance (alias)")
    
    # list
    subparsers.add_parser("list", help="List droplets")
    subparsers.add_parser("ls", help="List droplets (alias)")
    
    # create
    p_create = subparsers.add_parser("create", help="Create droplet")
    p_create.add_argument("name", help="Droplet name")
    p_create.add_argument("-r", "--region", default="sgp1", help="Region (default: sgp1)")
    p_create.add_argument("-s", "--size", default="s-1vcpu-512mb-10gb", help="Size slug")
    p_create.add_argument("-i", "--image", default="ubuntu-24-04-x64", help="Image slug")
    p_create.add_argument("-k", "--ssh-key", help="SSH public key string")
    
    # delete
    p_delete = subparsers.add_parser("delete", help="Delete droplet")
    p_delete.add_argument("id", type=int, help="Droplet ID")
    p_delete.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    
    # info
    p_info = subparsers.add_parser("info", help="Show droplet info")
    p_info.add_argument("id", type=int, help="Droplet ID")
    
    # power
    p_power = subparsers.add_parser("power", help="Power control")
    p_power.add_argument("action", choices=["on", "off", "reboot"])
    p_power.add_argument("id", type=int, help="Droplet ID")
    
    # regions
    subparsers.add_parser("regions", help="List regions")
    
    # sizes
    p_sizes = subparsers.add_parser("sizes", help="List sizes")
    p_sizes.add_argument("-a", "--all", action="store_true", help="Show all sizes")
    p_sizes.add_argument("-d", "--desc", action="store_true", help="Sort by price descending (largest first)")
    
    # keys
    subparsers.add_parser("keys", help="List SSH keys")
    
    # snapshots
    subparsers.add_parser("snapshots", help="List snapshots")
    subparsers.add_parser("snaps", help="List snapshots (alias)")
    
    # save (snapshot + delete)
    p_save = subparsers.add_parser("save", help="Snapshot droplet and delete it (saves cost)")
    p_save.add_argument("id", type=int, help="Droplet ID")
    p_save.add_argument("-n", "--name", help="Snapshot name")
    p_save.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    
    # restore
    p_restore = subparsers.add_parser("restore", help="Restore droplet from snapshot")
    p_restore.add_argument("snapshot_id", type=int, help="Snapshot ID")
    p_restore.add_argument("name", help="New droplet name")
    p_restore.add_argument("-r", "--region", default="sgp1", help="Region (default: sgp1)")
    p_restore.add_argument("-s", "--size", default="s-1vcpu-512mb-10gb", help="Size slug")
    
    # --- Reserved IP commands ---
    
    # ips (list)
    subparsers.add_parser("ips", help="List reserved IPs")
    
    # ip-create
    p_ip_create = subparsers.add_parser("ip-create", help="Create a reserved IP")
    p_ip_create.add_argument("-r", "--region", default="sgp1", help="Region (default: sgp1)")
    p_ip_create.add_argument("-d", "--droplet", type=int, help="Droplet ID to assign to")
    
    # ip-assign
    p_ip_assign = subparsers.add_parser("ip-assign", help="Assign reserved IP to droplet")
    p_ip_assign.add_argument("ip", help="Reserved IP address")
    p_ip_assign.add_argument("droplet_id", type=int, help="Droplet ID")
    
    # ip-unassign
    p_ip_unassign = subparsers.add_parser("ip-unassign", help="Unassign reserved IP")
    p_ip_unassign.add_argument("ip", help="Reserved IP address")
    
    # ip-delete
    p_ip_delete = subparsers.add_parser("ip-delete", help="Delete a reserved IP")
    p_ip_delete.add_argument("ip", help="Reserved IP address")
    p_ip_delete.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    
    args = parser.parse_args()
    
    if args.command in ("status", "st"):
        cmd_status(args)
    elif args.command == "account":
        cmd_account(args)
    elif args.command in ("balance", "billing"):
        cmd_balance(args)
    elif args.command in ("list", "ls"):
        cmd_list(args)
    elif args.command == "create":
        cmd_create(args)
    elif args.command == "delete":
        cmd_delete(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "power":
        cmd_power(args)
    elif args.command == "regions":
        cmd_regions(args)
    elif args.command == "sizes":
        cmd_sizes(args)
    elif args.command == "keys":
        cmd_keys(args)
    elif args.command in ("snapshots", "snaps"):
        cmd_snapshots(args)
    elif args.command == "save":
        cmd_save(args)
    elif args.command == "restore":
        cmd_restore(args)
    elif args.command == "ips":
        cmd_ips(args)
    elif args.command == "ip-create":
        cmd_ip_create(args)
    elif args.command == "ip-assign":
        cmd_ip_assign(args)
    elif args.command == "ip-unassign":
        cmd_ip_unassign(args)
    elif args.command == "ip-delete":
        cmd_ip_delete(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
