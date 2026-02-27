#!/usr/bin/env python3
"""Azure VM CLI - deallocate or restart VMs."""
import os
import sys
import argparse
from pathlib import Path

for _parent in Path(__file__).resolve().parents:
    if (_parent / "cred.json").exists():
        sys.path.insert(0, str(_parent / "linux" / "extra"))
        break

from cred_loader import get_azure

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.subscription import SubscriptionClient
except ImportError:
    print("Installing Azure SDK...")
    os.system("pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-subscription")
    from azure.identity import ClientSecretCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.subscription import SubscriptionClient


def get_clients():
    creds = get_azure()
    credential = ClientSecretCredential(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"]
    )
    sub_id = creds.get("subscription_id")
    if not sub_id:
        subs = list(SubscriptionClient(credential).subscriptions.list())
        sub_id = subs[0].subscription_id if subs else None
    if not sub_id:
        print("No subscription found!")
        sys.exit(1)
    return (ComputeManagementClient(credential, sub_id),
            NetworkManagementClient(credential, sub_id))


def deallocate(compute, network):
    """Deallocate all VMs (stops billing)."""
    vms = list(compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Deallocating {vm.name}...", end=" ", flush=True)
        compute.virtual_machines.begin_deallocate(rg, vm.name).result()
        print("done")
    print(f"\n{len(vms)} VM(s) deallocated.")


def start(compute, network):
    """Start all VMs."""
    vms = list(compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Starting {vm.name}...", end=" ", flush=True)
        compute.virtual_machines.begin_start(rg, vm.name).result()
        print("done")
    print(f"\n{len(vms)} VM(s) started.")


def restart(compute, network):
    """Restart all VMs."""
    vms = list(compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"Restarting {vm.name}...", end=" ", flush=True)
        compute.virtual_machines.begin_restart(rg, vm.name).result()
        print("done")
    print(f"\n{len(vms)} VM(s) restarted.")


def status(compute, network):
    """Show complete VM information."""
    vms = list(compute.virtual_machines.list_all())
    if not vms:
        print("No VMs found.")
        return
    
    for vm in vms:
        rg = vm.id.split('/')[4]
        instance = compute.virtual_machines.get(rg, vm.name, expand='instanceView')
        statuses = instance.instance_view.statuses if instance.instance_view else []
        power = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
        
        public_ip = None
        private_ip = None
        if instance.network_profile and instance.network_profile.network_interfaces:
            nic_id = instance.network_profile.network_interfaces[0].id
            nic_name = nic_id.split('/')[-1]
            nic_rg = nic_id.split('/')[4]
            nic = network.network_interfaces.get(nic_rg, nic_name)
            if nic.ip_configurations:
                ip_cfg = nic.ip_configurations[0]
                private_ip = ip_cfg.private_ip_address
                if ip_cfg.public_ip_address:
                    pip_id = ip_cfg.public_ip_address.id
                    pip_name = pip_id.split('/')[-1]
                    pip_rg = pip_id.split('/')[4]
                    pip = network.public_ip_addresses.get(pip_rg, pip_name)
                    public_ip = pip.ip_address
        
        os_type = instance.storage_profile.os_disk.os_type if instance.storage_profile else "Unknown"
        os_disk_size = instance.storage_profile.os_disk.disk_size_gb if instance.storage_profile and instance.storage_profile.os_disk else "N/A"
        
        print(f"\n{'='*50}")
        print(f"VM: {vm.name}")
        print(f"{'='*50}")
        print(f"  Resource Group: {rg}")
        print(f"  Location:       {vm.location}")
        print(f"  Size:           {vm.hardware_profile.vm_size}")
        print(f"  Status:         {power}")
        print(f"  OS:             {os_type}")
        print(f"  OS Disk:        {os_disk_size} GB")
        print(f"  Private IP:     {private_ip or 'N/A'}")
        print(f"  Public IP:      {public_ip or '(not allocated)'}")
        if public_ip:
            print(f"  SSH:            ssh azureuser@{public_ip}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Azure VM CLI")
    parser.add_argument("action", choices=["de", "deallocate", "start", "restart", "status"],
                        help="Action: de/deallocate, start, restart, status")
    args = parser.parse_args()

    compute, network = get_clients()
    actions = {
        "de": deallocate, "deallocate": deallocate,
        "start": start, "restart": restart, "status": status
    }
    actions[args.action](compute, network)
