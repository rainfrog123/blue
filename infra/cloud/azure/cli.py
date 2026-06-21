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


def cmd_traffic(args):
    """Show network traffic usage for VMs."""
    from azure.mgmt.monitor import MonitorManagementClient
    
    clients = get_clients()
    vms = list(clients.compute.virtual_machines.list_all())
    
    if not vms:
        print("No VMs found.")
        return
    
    monitor = MonitorManagementClient(clients.credential, clients.subscription_id)
    end_time = datetime.now(timezone.utc)
    start_30d = end_time - timedelta(days=30)
    start_7d = end_time - timedelta(days=7)
    
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_30d_str = start_30d.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_7d_str = start_7d.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    for vm in vms:
        print(f"\n{'='*50}")
        print(f"VM: {vm.name}")
        print(f"{'='*50}")
        
        # 30-day totals
        print(f"\nNetwork Traffic (Last 30 Days):")
        try:
            metrics = monitor.metrics.list(
                vm.id,
                timespan=f"{start_30d_str}/{end_str}",
                interval="P1D",
                metricnames="Network In Total,Network Out Total",
                aggregation="Total"
            )
            
            totals = {}
            for metric in metrics.value:
                total = sum(d.total for ts in metric.timeseries for d in ts.data if d.total)
                totals[metric.name.localized_value] = total
            
            net_in = totals.get("Network In Total", 0)
            net_out = totals.get("Network Out Total", 0)
            
            print(f"  In:    {net_in / (1024**3):.2f} GB ({net_in / (1024**2):.0f} MB)")
            print(f"  Out:   {net_out / (1024**3):.2f} GB ({net_out / (1024**2):.0f} MB)")
            print(f"  Total: {(net_in + net_out) / (1024**3):.2f} GB")
            
            # Free tier info (PAYG accounts get 100 GB free egress/month)
            free_limit_gb = 100
            out_gb = net_out / (1024**3)
            remaining = max(0, free_limit_gb - out_gb)
            pct_used = (out_gb / free_limit_gb) * 100
            print(f"\n  Free Tier (100 GB outbound/month):")
            print(f"    Used:      {out_gb:.2f} GB ({pct_used:.1f}%)")
            print(f"    Remaining: {remaining:.2f} GB")
            
        except Exception as e:
            print(f"  Error: {e}")
        
        # Daily breakdown
        print(f"\nDaily Breakdown (Last 7 Days):")
        try:
            metrics = monitor.metrics.list(
                vm.id,
                timespan=f"{start_7d_str}/{end_str}",
                interval="P1D",
                metricnames="Network In Total,Network Out Total",
                aggregation="Total"
            )
            
            data_by_date = {}
            for metric in metrics.value:
                for ts in metric.timeseries:
                    for data in ts.data:
                        if data.total and data.time_stamp:
                            date = data.time_stamp.strftime("%Y-%m-%d")
                            if date not in data_by_date:
                                data_by_date[date] = {"in": 0, "out": 0}
                            if "In" in metric.name.localized_value:
                                data_by_date[date]["in"] = data.total / (1024**2)
                            else:
                                data_by_date[date]["out"] = data.total / (1024**2)
            
            if data_by_date:
                print(f"  {'Date':<12} {'In (MB)':>10} {'Out (MB)':>10}")
                print(f"  {'-'*34}")
                for date in sorted(data_by_date.keys()):
                    d = data_by_date[date]
                    print(f"  {date:<12} {d['in']:>10.1f} {d['out']:>10.1f}")
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


def cmd_create_free(args):
    """Create a completely free Azure VM with IPv6-only (no public IPv4 charges)."""
    from azure.mgmt.compute.models import (
        VirtualMachine, HardwareProfile, StorageProfile, OSDisk,
        ImageReference, NetworkProfile, NetworkInterfaceReference,
        OSProfile, LinuxConfiguration, SshConfiguration, SshPublicKey,
        DiskCreateOptionTypes, CachingTypes, DeleteOptions
    )
    from azure.mgmt.network.models import (
        VirtualNetwork, Subnet, AddressSpace, PublicIPAddress,
        NetworkInterface, NetworkInterfaceIPConfiguration,
        NetworkSecurityGroup, SecurityRule
    )
    
    clients = get_clients()
    location = args.location
    rg_name = args.name
    vm_name = args.name
    username = args.username
    
    import os
    # Read SSH public key
    ssh_key_path = os.path.expanduser(args.ssh_key)
    try:
        with open(ssh_key_path, 'r') as f:
            ssh_pub_key = f.read().strip()
    except FileNotFoundError:
        print(f"Error: SSH key not found at {ssh_key_path}")
        print("Generate one with: ssh-keygen -t ed25519")
        return
    
    vm_size = args.size
    
    print(f"\n{'='*60}")
    print("Creating FREE Azure VM")
    print(f"{'='*60}")
    print(f"  Name:     {vm_name}")
    print(f"  Location: {location}")
    print(f"  Size:     {vm_size}")
    print(f"  Disk:     64 GB Premium SSD (P6)")
    print(f"  IP:       IPv6 only (free)")
    print()
    
    # 1. Create Resource Group
    print("1. Creating resource group...", end=" ", flush=True)
    clients.resource.resource_groups.create_or_update(rg_name, {"location": location})
    print("done")
    
    # 2. Create Network Security Group
    print("2. Creating network security group...", end=" ", flush=True)
    nsg_name = f"{vm_name}-nsg"
    nsg = clients.network.network_security_groups.begin_create_or_update(
        rg_name, nsg_name,
        NetworkSecurityGroup(
            location=location,
            security_rules=[
                SecurityRule(
                    name="AllowSSH",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    access="Allow",
                    priority=1000,
                    direction="Inbound"
                ),
                SecurityRule(
                    name="AllowSSH-IPv6",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="::/0",
                    destination_address_prefix="::/0",
                    access="Allow",
                    priority=1001,
                    direction="Inbound"
                )
            ]
        )
    ).result()
    print("done")
    
    # 3. Create VNet with IPv4 + IPv6
    print("3. Creating virtual network with IPv6...", end=" ", flush=True)
    vnet_name = f"{vm_name}-vnet"
    subnet_name = "default"
    
    vnet = clients.network.virtual_networks.begin_create_or_update(
        rg_name, vnet_name,
        VirtualNetwork(
            location=location,
            address_space=AddressSpace(
                address_prefixes=["10.0.0.0/16", "fd00:db8:deca::/48"]
            ),
            subnets=[
                Subnet(
                    name=subnet_name,
                    address_prefixes=["10.0.0.0/24", "fd00:db8:deca:deed::/64"],
                    network_security_group={"id": nsg.id}
                )
            ]
        )
    ).result()
    subnet_id = vnet.subnets[0].id
    print("done")
    
    # 4. Create Public IPv6 Address (FREE!)
    print("4. Creating public IPv6 address (free)...", end=" ", flush=True)
    ipv6_name = f"{vm_name}-ipv6"
    ipv6 = clients.network.public_ip_addresses.begin_create_or_update(
        rg_name, ipv6_name,
        PublicIPAddress(
            location=location,
            sku={"name": "Standard"},
            public_ip_allocation_method="Static",
            public_ip_address_version="IPv6"
        )
    ).result()
    print("done")
    
    # 5. Create Network Interface with IPv4 (private) + IPv6 (public)
    print("5. Creating network interface...", end=" ", flush=True)
    nic_name = f"{vm_name}-nic"
    nic = clients.network.network_interfaces.begin_create_or_update(
        rg_name, nic_name,
        NetworkInterface(
            location=location,
            ip_configurations=[
                NetworkInterfaceIPConfiguration(
                    name="ipconfig-ipv4",
                    subnet={"id": subnet_id},
                    private_ip_allocation_method="Dynamic",
                    private_ip_address_version="IPv4",
                    primary=True
                ),
                NetworkInterfaceIPConfiguration(
                    name="ipconfig-ipv6",
                    subnet={"id": subnet_id},
                    private_ip_allocation_method="Dynamic",
                    private_ip_address_version="IPv6",
                    public_ip_address={"id": ipv6.id}
                )
            ]
        )
    ).result()
    print("done")
    
    # 6. Create VM
    print("6. Creating virtual machine (this takes 2-3 minutes)...", end=" ", flush=True)
    zone = args.zone
    vm_params = VirtualMachine(
        location=location,
        zones=[zone] if zone else None,
        hardware_profile=HardwareProfile(vm_size=vm_size),
        storage_profile=StorageProfile(
            image_reference=ImageReference(
                publisher="Canonical",
                offer="ubuntu-24_04-lts",
                sku="server",
                version="latest"
            ),
            os_disk=OSDisk(
                name=f"{vm_name}-osdisk",
                caching=CachingTypes.READ_WRITE,
                create_option=DiskCreateOptionTypes.FROM_IMAGE,
                disk_size_gb=64,
                managed_disk={"storage_account_type": "Premium_LRS"},
                delete_option=DeleteOptions.DELETE
            )
        ),
        network_profile=NetworkProfile(
            network_interfaces=[
                NetworkInterfaceReference(
                    id=nic.id,
                    delete_option=DeleteOptions.DELETE
                )
            ]
        ),
        os_profile=OSProfile(
            computer_name=vm_name,
            admin_username=username,
            linux_configuration=LinuxConfiguration(
                disable_password_authentication=True,
                ssh=SshConfiguration(
                    public_keys=[
                        SshPublicKey(
                            path=f"/home/{username}/.ssh/authorized_keys",
                            key_data=ssh_pub_key
                        )
                    ]
                )
            )
        )
    )
    vm = clients.compute.virtual_machines.begin_create_or_update(
        rg_name, vm_name, vm_params
    ).result()
    print("done")
    
    # Get the actual IPv6 address
    ipv6_updated = clients.network.public_ip_addresses.get(rg_name, ipv6_name)
    ipv6_addr = ipv6_updated.ip_address or "(pending - check in a minute)"
    
    print(f"\n{'='*60}")
    print("FREE VM Created Successfully!")
    print(f"{'='*60}")
    print(f"  Resource Group: {rg_name}")
    print(f"  VM Name:        {vm_name}")
    print(f"  Location:       {location}")
    print(f"  Size:           {vm_size}")
    print(f"  OS Disk:        64 GB Premium SSD (P6)")
    print(f"  IPv6 Address:   {ipv6_addr}")
    print(f"  Username:       {username}")
    print()
    print("Cost: $0/month (750 free hours + 64GB P6 + free IPv6)")
    print()
    print("Connect via SSH:")
    print(f"  ssh -6 {username}@{ipv6_addr}")
    print()
    print("IMPORTANT: After first login, create swap (1GB RAM is low):")
    print("  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile")
    print("  sudo mkswap /swapfile && sudo swapon /swapfile")
    print("  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab")


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
    subparsers.add_parser("traffic", help="Show network traffic usage")
    
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
    
    # Free VM creation
    free_p = subparsers.add_parser("create-free", help="Create FREE VM (IPv6-only)")
    free_p.add_argument("--name", default="free-sg", help="VM and resource group name")
    free_p.add_argument("--location", default="southeastasia", help="Azure region (default: Singapore)")
    free_p.add_argument("--zone", default="1", help="Availability zone (1, 2, or 3)")
    free_p.add_argument("--size", default="Standard_B2ats_v2", help="VM size (default: B2ats_v2 - 2vCPU/1GB, free tier)")
    free_p.add_argument("--username", default="azureuser", help="Admin username")
    free_p.add_argument("--ssh-key", default="~/.ssh/id_ed25519.pub", help="Path to SSH public key")
    
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
        "traffic": cmd_traffic,
        "quota": cmd_quota,
        "delete-all": cmd_delete_all,
        "proxy-deploy": cmd_proxy_deploy,
        "proxy-status": cmd_proxy_status,
        "proxy-delete": cmd_proxy_delete,
        "create-free": cmd_create_free,
    }
    
    commands[args.command](args)


if __name__ == "__main__":
    main()
