#!/usr/bin/env python3
"""Azure CLI - unified management for VMs, resources, billing, and proxies."""
import sys
import argparse
from datetime import datetime, timedelta, timezone

from core import get_clients


def cmd_status(args):
    """Show VM status."""
    clients = get_clients()
    vms = list(clients.compute.virtual_machines.list_all())
    
    if not vms:
        print("No VMs found.")
        return
    
    for vm in vms:
        rg = vm.id.split('/')[4]
        instance = clients.compute.virtual_machines.get(rg, vm.name, expand='instanceView')
        statuses = instance.instance_view.statuses if instance.instance_view else []
        power = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
        
        public_ip = private_ip = None
        if instance.network_profile and instance.network_profile.network_interfaces:
            nic_id = instance.network_profile.network_interfaces[0].id
            nic_name, nic_rg = nic_id.split('/')[-1], nic_id.split('/')[4]
            try:
                nic = clients.network.network_interfaces.get(nic_rg, nic_name)
                if nic.ip_configurations:
                    ip_cfg = nic.ip_configurations[0]
                    private_ip = ip_cfg.private_ip_address
                    if ip_cfg.public_ip_address:
                        pip_id = ip_cfg.public_ip_address.id
                        pip = clients.network.public_ip_addresses.get(pip_id.split('/')[4], pip_id.split('/')[-1])
                        public_ip = pip.ip_address
            except Exception:
                pass
        
        os_type = instance.storage_profile.os_disk.os_type if instance.storage_profile else "Unknown"
        disk_size = instance.storage_profile.os_disk.disk_size_gb if instance.storage_profile and instance.storage_profile.os_disk else None
        
        print(f"\n{'='*50}")
        print(f"VM: {vm.name}")
        print(f"{'='*50}")
        print(f"  Resource Group: {rg}")
        print(f"  Location:       {vm.location}")
        print(f"  Size:           {vm.hardware_profile.vm_size}")
        print(f"  Status:         {power}")
        print(f"  OS:             {os_type}")
        print(f"  OS Disk:        {disk_size or 'N/A'} GB")
        print(f"  Private IP:     {private_ip or 'N/A'}")
        print(f"  Public IP:      {public_ip or '(not allocated)'}")
        if public_ip:
            print(f"  SSH:            ssh azureuser@{public_ip}")


def cmd_start(args):
    """Start all VMs."""
    clients = get_clients()
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Starting {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_start(rg, vm.name).result()
        print("done")


def cmd_stop(args):
    """Deallocate all VMs (stops billing)."""
    clients = get_clients()
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Deallocating {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_deallocate(rg, vm.name).result()
        print("done")


def cmd_restart(args):
    """Restart all VMs."""
    clients = get_clients()
    vms = list(clients.compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Restarting {vm.name}...", end=" ", flush=True)
        clients.compute.virtual_machines.begin_restart(rg, vm.name).result()
        print("done")


def cmd_sub(args):
    """Show subscription information."""
    clients = get_clients()
    sub = clients.subscription.subscriptions.get(clients.subscription_id)
    
    print(f"\n{'='*50}")
    print("Subscription")
    print(f"{'='*50}")
    print(f"  Name:           {sub.display_name}")
    print(f"  ID:             {sub.subscription_id}")
    print(f"  State:          {sub.state}")
    
    if hasattr(sub, 'subscription_policies') and sub.subscription_policies:
        p = sub.subscription_policies
        if hasattr(p, 'spending_limit'):
            print(f"  Spending Limit: {p.spending_limit}")
        if hasattr(p, 'quota_id'):
            print(f"  Offer Type:     {p.quota_id}")


def cmd_resources(args):
    """List all resources."""
    clients = get_clients()
    
    print(f"\n{'='*50}")
    print("Resource Groups")
    print(f"{'='*50}")
    rgs = list(clients.resource.resource_groups.list())
    if not rgs:
        print("  None")
    else:
        for rg in rgs:
            print(f"  {rg.name} ({rg.location})")
    
    print(f"\n{'='*50}")
    print("Resources")
    print(f"{'='*50}")
    resources = list(clients.resource.resources.list())
    if not resources:
        print("  None")
    else:
        by_type = {}
        for r in resources:
            t = r.type.split('/')[-1]
            by_type.setdefault(t, []).append(r.name)
        for t, names in sorted(by_type.items()):
            print(f"  {t}: {len(names)}")
            for n in names:
                print(f"    - {n}")


def cmd_cost(args):
    """Show cost information."""
    clients = get_clients()
    sub_id = clients.subscription_id
    today = datetime.now(timezone.utc)
    
    print(f"\n{'='*50}")
    print("Cost (Last 30 Days)")
    print(f"{'='*50}")
    
    query = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "time_period": {
            "from": (today - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z"),
            "to": today.strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "dataset": {
            "granularity": "None",
            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}
        }
    }
    
    try:
        result = clients.cost.query.usage(f"/subscriptions/{sub_id}", query)
        total = result.rows[0][0] if result.rows else 0
        print(f"  Total: ${total:.2f}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print(f"\n{'='*50}")
    print("Daily Cost (Last 7 Days)")
    print(f"{'='*50}")
    
    query["dataset"]["granularity"] = "Daily"
    query["time_period"]["from"] = (today - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z")
    
    try:
        result = clients.cost.query.usage(f"/subscriptions/{sub_id}", query)
        if result.rows:
            for row in result.rows:
                c, d = row[0], row[1]
                if isinstance(d, int):
                    d = f"{str(d)[:4]}-{str(d)[4:6]}-{str(d)[6:8]}"
                else:
                    d = str(d)[:10]
                print(f"  {d}: ${c:.2f}")
        else:
            print("  No data")
    except Exception as e:
        print(f"  Error: {e}")


def cmd_quota(args):
    """Check compute quota for a location."""
    clients = get_clients()
    location = args.location
    
    print(f"\n{'='*60}")
    print(f"Compute Quota: {location}")
    print(f"{'='*60}")
    
    try:
        usages = list(clients.compute.usage.list(location))
        usages = [u for u in usages if any(x in u.name.localized_value.lower() for x in ['core', 'cpu', 'vcpu'])]
        
        print(f"\n{'Resource':<40} {'Used':>8} {'Limit':>8} {'Avail':>8}")
        print("-" * 66)
        
        for usage in sorted(usages, key=lambda x: x.name.localized_value):
            name = usage.name.localized_value[:40]
            avail = usage.limit - usage.current_value
            flag = " *" if "lowpriority" in name.lower().replace(" ", "") else ""
            print(f"{name:<40} {usage.current_value:>8} {usage.limit:>8} {avail:>8}{flag}")
    except Exception as e:
        print(f"  Error: {e}")


def cmd_delete_all(args):
    """Delete all resource groups (removes all resources)."""
    clients = get_clients()
    
    if not args.confirm:
        print("WARNING: This will delete ALL resources!")
        print("Run with --confirm to proceed.")
        return
    
    rgs = list(clients.resource.resource_groups.list())
    if not rgs:
        print("No resource groups to delete.")
        return
    
    for rg in rgs:
        print(f"Deleting {rg.name}...", end=" ", flush=True)
        try:
            clients.resource.resource_groups.begin_delete(rg.name)
            print("started")
        except Exception as e:
            print(f"error: {e}")
    
    print("\nDeletion initiated. Resources will be removed in background.")


def cmd_proxy_deploy(args):
    """Deploy SOCKS5 proxy container."""
    from azure.mgmt.containerinstance.models import (
        ContainerGroup, Container, ContainerPort, ResourceRequirements,
        ResourceRequests, IpAddress, Port, EnvironmentVariable, OperatingSystemTypes
    )
    
    clients = get_clients()
    location = args.location
    rg_name = f"socks5-{location[:3]}"
    cg_name = f"socks5-{location[:3]}"
    
    print(f"Creating resource group '{rg_name}'...")
    clients.resource.resource_groups.create_or_update(rg_name, {"location": location})
    
    container = Container(
        name=cg_name,
        image="serjs/go-socks5-proxy",
        resources=ResourceRequirements(requests=ResourceRequests(cpu=1.0, memory_in_gb=1.0)),
        ports=[ContainerPort(port=1080, protocol="TCP")],
        environment_variables=[
            EnvironmentVariable(name="PROXY_USER", value=args.user),
            EnvironmentVariable(name="PROXY_PASSWORD", secure_value=args.password),
        ],
    )
    
    group = ContainerGroup(
        location=location,
        containers=[container],
        os_type=OperatingSystemTypes.linux,
        ip_address=IpAddress(ports=[Port(port=1080, protocol="TCP")], type="Public"),
        restart_policy="Always",
    )
    
    print(f"Deploying container...")
    result = clients.container.container_groups.begin_create_or_update(rg_name, cg_name, group).result()
    ip = result.ip_address.ip if result.ip_address else "(pending)"
    
    print(f"\n{'='*50}")
    print("SOCKS5 Proxy Deployed")
    print(f"{'='*50}")
    print(f"  Host:     {ip}")
    print(f"  Port:     1080")
    print(f"  User:     {args.user}")
    print(f"  Password: {args.password}")
    print(f"\n  curl --socks5-hostname {ip}:1080 --proxy-user {args.user}:{args.password} http://ifconfig.me")


def cmd_proxy_status(args):
    """Show SOCKS5 proxy status."""
    clients = get_clients()
    
    print(f"\n{'='*50}")
    print("SOCKS5 Proxy Containers")
    print(f"{'='*50}")
    
    found = False
    for rg in clients.resource.resource_groups.list():
        if rg.name.startswith("socks5-"):
            try:
                cgs = list(clients.container.container_groups.list_by_resource_group(rg.name))
                for cg in cgs:
                    found = True
                    ip = cg.ip_address.ip if cg.ip_address else "(none)"
                    state = cg.provisioning_state
                    print(f"\n  {cg.name} [{rg.name}]")
                    print(f"    Location: {cg.location}")
                    print(f"    State:    {state}")
                    print(f"    IP:       {ip}:1080")
            except Exception:
                pass
    
    if not found:
        print("  No proxy containers found.")


def cmd_proxy_delete(args):
    """Delete SOCKS5 proxy."""
    clients = get_clients()
    
    for rg in list(clients.resource.resource_groups.list()):
        if rg.name.startswith("socks5-"):
            print(f"Deleting {rg.name}...", end=" ", flush=True)
            try:
                clients.resource.resource_groups.begin_delete(rg.name)
                print("started")
            except Exception as e:
                print(f"error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Azure CLI", formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # VM commands
    subparsers.add_parser("status", help="Show VM status")
    subparsers.add_parser("start", help="Start all VMs")
    subparsers.add_parser("stop", help="Deallocate all VMs")
    subparsers.add_parser("restart", help="Restart all VMs")
    
    # Account commands
    subparsers.add_parser("sub", help="Show subscription info")
    subparsers.add_parser("resources", help="List all resources")
    subparsers.add_parser("cost", help="Show cost info")
    
    # Quota
    quota_p = subparsers.add_parser("quota", help="Check compute quota")
    quota_p.add_argument("location", nargs="?", default="southeastasia", help="Azure region")
    
    # Cleanup
    delete_p = subparsers.add_parser("delete-all", help="Delete all resources")
    delete_p.add_argument("--confirm", action="store_true", help="Confirm deletion")
    
    # Proxy commands
    proxy_deploy = subparsers.add_parser("proxy-deploy", help="Deploy SOCKS5 proxy")
    proxy_deploy.add_argument("--location", default="germanywestcentral", help="Azure region")
    proxy_deploy.add_argument("--user", default="blue", help="Proxy username")
    proxy_deploy.add_argument("--password", default="proxypass123", help="Proxy password")
    
    subparsers.add_parser("proxy-status", help="Show proxy status")
    subparsers.add_parser("proxy-delete", help="Delete proxy")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    commands = {
        "status": cmd_status,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "sub": cmd_sub,
        "resources": cmd_resources,
        "cost": cmd_cost,
        "quota": cmd_quota,
        "delete-all": cmd_delete_all,
        "proxy-deploy": cmd_proxy_deploy,
        "proxy-status": cmd_proxy_status,
        "proxy-delete": cmd_proxy_delete,
    }
    
    commands[args.command](args)


if __name__ == "__main__":
    main()
