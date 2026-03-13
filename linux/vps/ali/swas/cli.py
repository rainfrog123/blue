#!/usr/bin/env python3
# %% Alibaba Cloud SWAS CLI - Simple Application Server Management
"""
CLI for managing Alibaba Cloud SWAS (轻量应用服务器) instances.

Usage:
    python cli.py info              # Show instance details
    python cli.py start             # Start instance
    python cli.py stop              # Stop instance
    python cli.py reboot            # Reboot instance
    python cli.py snapshots         # List snapshots
    python cli.py snapshot create   # Create snapshot
    python cli.py disks             # List disks
    python cli.py firewall          # List firewall rules
"""
import sys
from pathlib import Path

# Add credential loader to path (swas -> ali -> vps -> linux -> extra)
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "extra"))
from cred_loader import get_alibaba

from alibabacloud_swas_open20200601 import models as swas_models
from alibabacloud_swas_open20200601.client import Client as SwasClient
from alibabacloud_tea_openapi import models as open_api_models

# Configuration - Singapore region
REGION_ID = "ap-southeast-1"
INSTANCE_ID = "6911f5dbf7d440d8ac63e9ac1706d406"

# Load credentials and create client
_alibaba = get_alibaba()
_config = open_api_models.Config(
    access_key_id=_alibaba["access_key_id"],
    access_key_secret=_alibaba["access_key_secret"],
)
_config.endpoint = f"swas.{REGION_ID}.aliyuncs.com"
client = SwasClient(_config)


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"SWAS (轻量应用服务器) - {title}")
    print(f"{'='*60}")
    print(f"Region: {REGION_ID} | Instance: {INSTANCE_ID[:12]}...")
    print(f"{'='*60}\n")


# %% Instance Operations
def list_instances():
    """List all SWAS instances."""
    print_header("Instances")
    req = swas_models.ListInstancesRequest(region_id=REGION_ID)
    resp = client.list_instances(req)
    for inst in resp.body.instances:
        spec = inst.resource_spec
        print(f"ID:     {inst.instance_id}")
        print(f"Name:   {inst.instance_name}")
        print(f"Status: {inst.status}")
        print(f"IP:     {inst.public_ip_address} (public) / {inst.inner_ip_address} (private)")
        print(f"Spec:   {spec.cpu} vCPU / {spec.memory} GiB / {spec.disk_size} GiB {spec.disk_category}")
        print(f"Expiry: {inst.expired_time}")
        print("-" * 40)
    return resp.body.instances


def get_instance(instance_id: str = INSTANCE_ID):
    """Get instance details."""
    print_header("Instance Details")
    req = swas_models.ListInstancesRequest(
        region_id=REGION_ID,
        instance_ids=f'["{instance_id}"]'
    )
    resp = client.list_instances(req)
    if resp.body.instances:
        inst = resp.body.instances[0]
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
    return None


def start_instance(instance_id: str = INSTANCE_ID):
    """Start the instance."""
    print_header("Starting Instance")
    req = swas_models.StartInstanceRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.start_instance(req)
    print(f"Start requested: {resp.body}")
    return resp


def stop_instance(instance_id: str = INSTANCE_ID):
    """Stop the instance."""
    print_header("Stopping Instance")
    req = swas_models.StopInstanceRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.stop_instance(req)
    print(f"Stop requested: {resp.body}")
    return resp


def reboot_instance(instance_id: str = INSTANCE_ID):
    """Reboot the instance."""
    print_header("Rebooting Instance")
    req = swas_models.RebootInstanceRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.reboot_instance(req)
    print(f"Reboot requested: {resp.body}")
    return resp


# %% Snapshot Operations
def list_snapshots(instance_id: str = INSTANCE_ID):
    """List snapshots for the instance."""
    print_header("Snapshots")
    req = swas_models.ListSnapshotsRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.list_snapshots(req)
    if not resp.body.snapshots:
        print("No snapshots found.")
        return []
    for snap in resp.body.snapshots:
        print(f"ID:      {snap.snapshot_id}")
        print(f"Name:    {snap.snapshot_name}")
        print(f"Status:  {snap.status}")
        print(f"Created: {snap.creation_time}")
        print(f"Disk ID: {snap.source_disk_id}")
        print("-" * 40)
    return resp.body.snapshots


def create_snapshot(instance_id: str = INSTANCE_ID, name: str = None):
    """Create a snapshot of the instance."""
    print_header("Creating Snapshot")
    if name is None:
        from datetime import datetime
        name = f"snap-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    req = swas_models.CreateSnapshotRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        snapshot_name=name
    )
    resp = client.create_snapshot(req)
    print(f"Snapshot created: {resp.body.snapshot_id}")
    return resp


def delete_snapshot(snapshot_id: str):
    """Delete a snapshot."""
    print_header("Deleting Snapshot")
    req = swas_models.DeleteSnapshotRequest(
        region_id=REGION_ID,
        snapshot_id=snapshot_id
    )
    resp = client.delete_snapshot(req)
    print(f"Snapshot deleted: {snapshot_id}")
    return resp


# %% Disk Operations
def list_disks(instance_id: str = INSTANCE_ID):
    """List disks for the instance."""
    print_header("Disks")
    req = swas_models.ListDisksRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.list_disks(req)
    for disk in resp.body.disks:
        print(f"ID:       {disk.disk_id}")
        print(f"Name:     {disk.disk_name}")
        print(f"Size:     {disk.size} GiB")
        print(f"Type:     {disk.disk_type} / {disk.category}")
        print(f"Status:   {disk.status}")
        print("-" * 40)
    return resp.body.disks


# %% Firewall Operations
def list_firewall_rules(instance_id: str = INSTANCE_ID):
    """List firewall rules for the instance."""
    print_header("Firewall Rules")
    req = swas_models.ListFirewallRulesRequest(
        region_id=REGION_ID,
        instance_id=instance_id
    )
    resp = client.list_firewall_rules(req)
    for rule in resp.body.firewall_rules:
        print(f"Rule ID:  {rule.rule_id}")
        print(f"Port:     {rule.port}")
        print(f"Protocol: {rule.rule_protocol}")
        print(f"Policy:   {rule.policy}")
        print(f"Remark:   {rule.remark or '-'}")
        print("-" * 40)
    return resp.body.firewall_rules


def add_firewall_rule(port: str, protocol: str = "TCP", remark: str = "", instance_id: str = INSTANCE_ID):
    """Add a firewall rule."""
    print_header("Adding Firewall Rule")
    req = swas_models.CreateFirewallRuleRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        port=port,
        rule_protocol=protocol,
        remark=remark
    )
    resp = client.create_firewall_rule(req)
    print(f"Firewall rule added: {port}/{protocol}")
    return resp


# %% Run Command
def run_command(command: str, instance_id: str = INSTANCE_ID):
    """Run a command on the instance via cloud assistant."""
    print_header("Running Command")
    req = swas_models.RunCommandRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        command_content=command,
        type="RunShellScript"
    )
    resp = client.run_command(req)
    print(f"Command invoked: {resp.body.invoke_id}")
    return resp


# %% CLI Entry Point
def main():
    import argparse
    parser = argparse.ArgumentParser(description="SWAS CLI - 轻量应用服务器")
    parser.add_argument("command", nargs="?", default="info",
                        choices=["info", "list", "start", "stop", "reboot",
                                 "snapshots", "snapshot", "disks", "firewall", "run"])
    parser.add_argument("subcommand", nargs="?", help="Subcommand (e.g., create, delete)")
    parser.add_argument("--name", "-n", help="Name for snapshot")
    parser.add_argument("--id", help="Snapshot ID for deletion")
    parser.add_argument("--port", "-p", help="Port for firewall rule")
    parser.add_argument("--cmd", "-c", help="Command to run")
    args = parser.parse_args()

    if args.command == "info":
        get_instance()
    elif args.command == "list":
        list_instances()
    elif args.command == "start":
        start_instance()
    elif args.command == "stop":
        stop_instance()
    elif args.command == "reboot":
        reboot_instance()
    elif args.command == "snapshots":
        list_snapshots()
    elif args.command == "snapshot":
        if args.subcommand == "create":
            create_snapshot(name=args.name)
        elif args.subcommand == "delete" and args.id:
            delete_snapshot(args.id)
        else:
            list_snapshots()
    elif args.command == "disks":
        list_disks()
    elif args.command == "firewall":
        if args.subcommand == "add" and args.port:
            add_firewall_rule(args.port)
        else:
            list_firewall_rules()
    elif args.command == "run" and args.cmd:
        run_command(args.cmd)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
