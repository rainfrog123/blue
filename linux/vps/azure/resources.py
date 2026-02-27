#%% Imports and Setup
import os
import sys
import json
from pathlib import Path

_file = Path(__file__).resolve()
AZURE_DIR = _file.parent
for _parent in _file.parents:
    if (_parent / "cred.json").exists():
        sys.path.insert(0, str(_parent / "linux" / "extra"))
        break

from cred_loader import get_azure

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
except ImportError:
    print("Installing Azure SDK packages...")
    os.system("pip install --break-system-packages azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network")
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient

#%% Load Defaults
DEFAULTS_FILE = AZURE_DIR / "vm_defaults.json"
DEFAULTS = {}
if DEFAULTS_FILE.exists():
    with open(DEFAULTS_FILE) as f:
        DEFAULTS = json.load(f)

DEFAULT_RG = DEFAULTS.get("resource_group", "plan")
DEFAULT_LOCATION = DEFAULTS.get("location", "japaneast")
DEFAULT_VM = DEFAULTS.get("vm_name", "blue")

#%% Initialize Clients
creds = get_azure()
credential = ClientSecretCredential(
    tenant_id=creds["tenant_id"],
    client_id=creds["client_id"],
    client_secret=creds["client_secret"]
)
SUBSCRIPTION_ID = creds.get("subscription_id", DEFAULTS.get("subscription_id", "79c81b4b-ee78-49de-9cba-af5f987e6b38"))

resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
compute_client = ComputeManagementClient(credential, SUBSCRIPTION_ID)
network_client = NetworkManagementClient(credential, SUBSCRIPTION_ID)

print(f"Azure: subscription {SUBSCRIPTION_ID[:8]}...")

#%% Resource Listing Functions
def list_all():
    """List all Azure resources."""
    list_resource_groups()
    list_vms()
    list_vnets()
    list_public_ips()
    list_nics()
    list_disks()
    list_nsgs()

def list_resource_groups():
    """List all resource groups."""
    print(f"\n{'='*70}")
    print("RESOURCE GROUPS")
    print(f"{'='*70}")
    groups = list(resource_client.resource_groups.list())
    if not groups:
        print("  (none)")
        return []
    for rg in groups:
        print(f"  {rg.name:<30} [{rg.location}]")
    return groups

def list_vms(resource_group: str = None):
    """List virtual machines."""
    print(f"\n{'='*70}")
    print(f"VIRTUAL MACHINES{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        vms = list(compute_client.virtual_machines.list(resource_group))
    else:
        vms = list(compute_client.virtual_machines.list_all())
    
    if not vms:
        print("  (none)")
        return []
    
    print(f"  {'Name':<20} {'RG':<15} {'Location':<12} {'Size':<22} {'State'}")
    print(f"  {'-'*20} {'-'*15} {'-'*12} {'-'*22} {'-'*15}")
    
    for vm in vms:
        rg = vm.id.split('/')[4]
        vm_detail = compute_client.virtual_machines.get(rg, vm.name, expand='instanceView')
        statuses = vm_detail.instance_view.statuses if vm_detail.instance_view else []
        power = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
        print(f"  {vm.name:<20} {rg:<15} {vm.location:<12} {vm.hardware_profile.vm_size:<22} {power}")
    return vms

def list_vnets(resource_group: str = None):
    """List virtual networks."""
    print(f"\n{'='*70}")
    print(f"VIRTUAL NETWORKS{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        vnets = list(network_client.virtual_networks.list(resource_group))
    else:
        vnets = list(network_client.virtual_networks.list_all())
    
    if not vnets:
        print("  (none)")
        return []
    
    for vnet in vnets:
        rg = vnet.id.split('/')[4]
        prefixes = ', '.join(vnet.address_space.address_prefixes) if vnet.address_space else 'N/A'
        subnets = [s.name for s in (vnet.subnets or [])]
        print(f"  {vnet.name:<30} [{rg}]")
        print(f"    Address: {prefixes}")
        if subnets:
            print(f"    Subnets: {', '.join(subnets)}")
    return vnets

def list_public_ips(resource_group: str = None):
    """List public IP addresses."""
    print(f"\n{'='*70}")
    print(f"PUBLIC IPs{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        ips = list(network_client.public_ip_addresses.list(resource_group))
    else:
        ips = list(network_client.public_ip_addresses.list_all())
    
    if not ips:
        print("  (none)")
        return []
    
    for ip in ips:
        rg = ip.id.split('/')[4]
        addr = ip.ip_address or '(not allocated)'
        sku = ip.sku.name if ip.sku else 'N/A'
        alloc = ip.public_ip_allocation_method or 'N/A'
        print(f"  {ip.name:<30} [{rg}] {addr:<16} {sku}/{alloc}")
    return ips

def list_nics(resource_group: str = None):
    """List network interfaces."""
    print(f"\n{'='*70}")
    print(f"NETWORK INTERFACES{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        nics = list(network_client.network_interfaces.list(resource_group))
    else:
        nics = list(network_client.network_interfaces.list_all())
    
    if not nics:
        print("  (none)")
        return []
    
    for nic in nics:
        rg = nic.id.split('/')[4]
        private_ip = nic.ip_configurations[0].private_ip_address if nic.ip_configurations else 'N/A'
        vm_ref = nic.virtual_machine.id.split('/')[-1] if nic.virtual_machine else '(unattached)'
        print(f"  {nic.name:<30} [{rg}] {private_ip:<16} VM: {vm_ref}")
    return nics

def list_disks(resource_group: str = None):
    """List managed disks."""
    print(f"\n{'='*70}")
    print(f"DISKS{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        disks = list(compute_client.disks.list_by_resource_group(resource_group))
    else:
        disks = list(compute_client.disks.list())
    
    if not disks:
        print("  (none)")
        return []
    
    for disk in disks:
        rg = disk.id.split('/')[4]
        size = disk.disk_size_gb or 0
        sku = disk.sku.name if disk.sku else 'N/A'
        print(f"  {disk.name:<40} [{rg}] {size}GB {sku} ({disk.disk_state})")
    return disks

def list_nsgs(resource_group: str = None):
    """List network security groups."""
    print(f"\n{'='*70}")
    print(f"NETWORK SECURITY GROUPS{' in ' + resource_group if resource_group else ''}")
    print(f"{'='*70}")
    
    if resource_group:
        nsgs = list(network_client.network_security_groups.list(resource_group))
    else:
        nsgs = list(network_client.network_security_groups.list_all())
    
    if not nsgs:
        print("  (none)")
        return []
    
    for nsg in nsgs:
        rg = nsg.id.split('/')[4]
        rules = len(nsg.security_rules) if nsg.security_rules else 0
        print(f"  {nsg.name:<30} [{rg}] {rules} custom rules")
    return nsgs

#%% VM Details
def vm_info(vm_name: str = None, resource_group: str = None):
    """Get detailed info about a VM."""
    vm_name = vm_name or DEFAULT_VM
    resource_group = resource_group or DEFAULT_RG
    
    print(f"\n{'='*70}")
    print(f"VM DETAILS: {vm_name}")
    print(f"{'='*70}")
    
    try:
        vm = compute_client.virtual_machines.get(resource_group, vm_name, expand='instanceView')
    except Exception as e:
        print(f"  VM not found: {e}")
        return None
    
    statuses = vm.instance_view.statuses if vm.instance_view else []
    power = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
    
    print(f"  Name:           {vm.name}")
    print(f"  Resource Group: {resource_group}")
    print(f"  Location:       {vm.location}")
    print(f"  Size:           {vm.hardware_profile.vm_size}")
    print(f"  Power State:    {power}")
    
    if vm.storage_profile:
        os_disk = vm.storage_profile.os_disk
        print(f"\n  OS Disk:")
        print(f"    Name:         {os_disk.name}")
        print(f"    Size:         {os_disk.disk_size_gb or 'N/A'} GB")
        print(f"    OS Type:      {os_disk.os_type}")
    
    if vm.network_profile and vm.network_profile.network_interfaces:
        print(f"\n  Network Interfaces:")
        for nic_ref in vm.network_profile.network_interfaces:
            nic_name = nic_ref.id.split('/')[-1]
            try:
                nic = network_client.network_interfaces.get(resource_group, nic_name)
                for ip_config in nic.ip_configurations:
                    private_ip = ip_config.private_ip_address
                    public_ip = None
                    if ip_config.public_ip_address:
                        pip_name = ip_config.public_ip_address.id.split('/')[-1]
                        pip = network_client.public_ip_addresses.get(resource_group, pip_name)
                        public_ip = pip.ip_address
                    print(f"    {nic_name}: {private_ip} (public: {public_ip or 'none'})")
            except:
                print(f"    {nic_name}")
    
    return vm

#%% Resource Summary JSON
def get_resources_json():
    """Get all resources as a JSON structure."""
    resources = {
        "subscription_id": SUBSCRIPTION_ID,
        "resource_groups": [],
        "vms": [],
        "vnets": [],
        "public_ips": [],
        "nics": [],
        "disks": [],
        "nsgs": []
    }
    
    for rg in resource_client.resource_groups.list():
        resources["resource_groups"].append({
            "name": rg.name,
            "location": rg.location
        })
    
    for vm in compute_client.virtual_machines.list_all():
        rg = vm.id.split('/')[4]
        resources["vms"].append({
            "name": vm.name,
            "resource_group": rg,
            "location": vm.location,
            "size": vm.hardware_profile.vm_size
        })
    
    for vnet in network_client.virtual_networks.list_all():
        rg = vnet.id.split('/')[4]
        resources["vnets"].append({
            "name": vnet.name,
            "resource_group": rg,
            "address_space": vnet.address_space.address_prefixes if vnet.address_space else []
        })
    
    for ip in network_client.public_ip_addresses.list_all():
        rg = ip.id.split('/')[4]
        resources["public_ips"].append({
            "name": ip.name,
            "resource_group": rg,
            "ip_address": ip.ip_address
        })
    
    for nic in network_client.network_interfaces.list_all():
        rg = nic.id.split('/')[4]
        resources["nics"].append({
            "name": nic.name,
            "resource_group": rg,
            "private_ip": nic.ip_configurations[0].private_ip_address if nic.ip_configurations else None
        })
    
    for disk in compute_client.disks.list():
        rg = disk.id.split('/')[4]
        resources["disks"].append({
            "name": disk.name,
            "resource_group": rg,
            "size_gb": disk.disk_size_gb,
            "state": disk.disk_state
        })
    
    for nsg in network_client.network_security_groups.list_all():
        rg = nsg.id.split('/')[4]
        resources["nsgs"].append({
            "name": nsg.name,
            "resource_group": rg,
            "rules": len(nsg.security_rules) if nsg.security_rules else 0
        })
    
    return resources

#%% Interactive Usage
if __name__ == "__main__":
    print(f"""
{'='*70}
Azure Resources - Default: RG={DEFAULT_RG}, VM={DEFAULT_VM}, Location={DEFAULT_LOCATION}
{'='*70}

Usage:
    list_all()                    # List all resources
    list_vms()                    # List all VMs
    list_vms("{DEFAULT_RG}")            # List VMs in specific RG
    list_vnets()                  # List virtual networks
    list_public_ips()             # List public IPs
    list_nics()                   # List network interfaces
    list_disks()                  # List managed disks
    list_nsgs()                   # List NSGs
    
    vm_info()                     # Details for default VM ({DEFAULT_VM})
    vm_info("myvm", "myrg")       # Details for specific VM
    
    get_resources_json()          # Get all as JSON dict
""")
    
    list_all()
