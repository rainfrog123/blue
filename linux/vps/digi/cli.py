#!/usr/bin/env python3
"""DigitalOcean CLI for droplet management."""

import argparse
import sys

import helpers


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
    
    # Handle SSH key
    ssh_key_ids = []
    if args.ssh_key:
        print(f"  SSH Key: registering...")
        key = helpers.find_or_create_ssh_key("cli-key", args.ssh_key)
        ssh_key_ids.append(key["id"])
        print(f"  SSH Key ID: {key['id']} ({key['name']})")
    
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
    print(f"{'Slug':<25} {'vCPU':<6} {'RAM':<8} {'Disk':<8} {'$/mo'}")
    print("-" * 60)
    for s in sizes[:20]:
        print(f"{s['slug']:<25} {s['vcpus']:<6} {s['memory']:<8} {s['disk']:<8} ${s['price_monthly']}")


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


def main():
    parser = argparse.ArgumentParser(description="DigitalOcean CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
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
    subparsers.add_parser("sizes", help="List sizes")
    
    # keys
    subparsers.add_parser("keys", help="List SSH keys")
    
    args = parser.parse_args()
    
    if args.command in ("list", "ls"):
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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
