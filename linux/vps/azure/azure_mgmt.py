#%% Imports and Setup
import os
import sys
from pathlib import Path

# Find blue root (contains cred.json) and add to path for imports
_file = Path(__file__).resolve()
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
    from azure.mgmt.subscription import SubscriptionClient
except ImportError:
    print("Installing Azure SDK packages...")
    os.system("pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-subscription")
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.subscription import SubscriptionClient

#%% Load Credentials
creds = get_azure()

CLIENT_ID = creds["client_id"]
TENANT_ID = creds["tenant_id"]
CLIENT_SECRET = creds["client_secret"]

credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)

print(f"Authenticated with Azure (Tenant: {TENANT_ID[:8]}...)")

#%% Get Subscription
SUBSCRIPTION_ID = creds.get("subscription_id")

if not SUBSCRIPTION_ID:
    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())
    SUBSCRIPTION_ID = subscriptions[0].subscription_id if subscriptions else None

print(f"Using subscription: {SUBSCRIPTION_ID}")

#%% Initialize Management Clients
if SUBSCRIPTION_ID:
    resource_client = ResourceManagementClient(credential, SUBSCRIPTION_ID)
    compute_client = ComputeManagementClient(credential, SUBSCRIPTION_ID)
    network_client = NetworkManagementClient(credential, SUBSCRIPTION_ID)

#%% List Resource Groups
def list_resource_groups():
    print(f"\n{'='*60}")
    print("Resource Groups:")
    print(f"{'='*60}")
    groups = list(resource_client.resource_groups.list())
    if not groups:
        print("  (no resource groups)")
    for rg in groups:
        print(f"  [{rg.location}] {rg.name}")
    return groups

if SUBSCRIPTION_ID:
    resource_groups = list_resource_groups()

#%% List Virtual Machines
def list_vms():
    print(f"\n{'='*60}")
    print("Virtual Machines:")
    print(f"{'='*60}")
    vms = list(compute_client.virtual_machines.list_all())
    if not vms:
        print("  (no VMs)")
    for vm in vms:
        rg = vm.id.split('/')[4]
        print(f"  [{rg}] {vm.name} - {vm.location} ({vm.hardware_profile.vm_size})")
    return vms

if SUBSCRIPTION_ID:
    vms = list_vms()

#%% Get VM Details
def get_vm_status(resource_group: str, vm_name: str):
    vm = compute_client.virtual_machines.get(resource_group, vm_name, expand='instanceView')
    statuses = vm.instance_view.statuses if vm.instance_view else []
    power_state = next((s.display_status for s in statuses if s.code.startswith('PowerState')), 'Unknown')
    return {
        'name': vm.name,
        'location': vm.location,
        'size': vm.hardware_profile.vm_size,
        'power_state': power_state,
        'os_type': vm.storage_profile.os_disk.os_type,
    }

#%% VM Power Operations
def start_vm(resource_group: str, vm_name: str):
    print(f"Starting VM: {vm_name}...")
    poller = compute_client.virtual_machines.begin_start(resource_group, vm_name)
    poller.result()
    print(f"VM {vm_name} started.")

def stop_vm(resource_group: str, vm_name: str, deallocate: bool = True):
    print(f"Stopping VM: {vm_name}...")
    if deallocate:
        poller = compute_client.virtual_machines.begin_deallocate(resource_group, vm_name)
    else:
        poller = compute_client.virtual_machines.begin_power_off(resource_group, vm_name)
    poller.result()
    print(f"VM {vm_name} stopped.")

def restart_vm(resource_group: str, vm_name: str):
    print(f"Restarting VM: {vm_name}...")
    poller = compute_client.virtual_machines.begin_restart(resource_group, vm_name)
    poller.result()
    print(f"VM {vm_name} restarted.")

#%% List Network Resources
def list_vnets():
    print(f"\n{'='*60}")
    print("Virtual Networks:")
    print(f"{'='*60}")
    vnets = list(network_client.virtual_networks.list_all())
    if not vnets:
        print("  (no VNets)")
    for vnet in vnets:
        rg = vnet.id.split('/')[4]
        prefixes = ', '.join(vnet.address_space.address_prefixes) if vnet.address_space else 'N/A'
        print(f"  [{rg}] {vnet.name} - {prefixes}")
    return vnets

def list_public_ips():
    print(f"\n{'='*60}")
    print("Public IP Addresses:")
    print(f"{'='*60}")
    ips = list(network_client.public_ip_addresses.list_all())
    if not ips:
        print("  (no public IPs)")
    for ip in ips:
        rg = ip.id.split('/')[4]
        addr = ip.ip_address or '(not allocated)'
        print(f"  [{rg}] {ip.name} - {addr}")
    return ips

def list_nsgs():
    print(f"\n{'='*60}")
    print("Network Security Groups:")
    print(f"{'='*60}")
    nsgs = list(network_client.network_security_groups.list_all())
    if not nsgs:
        print("  (no NSGs)")
    for nsg in nsgs:
        rg = nsg.id.split('/')[4]
        rule_count = len(nsg.security_rules) if nsg.security_rules else 0
        print(f"  [{rg}] {nsg.name} - {rule_count} rules")
    return nsgs

#%% Create Resource Group
def create_resource_group(name: str, location: str = "eastus"):
    print(f"Creating resource group: {name} in {location}...")
    rg = resource_client.resource_groups.create_or_update(
        name,
        {"location": location}
    )
    print(f"Resource group {name} created.")
    return rg

#%% Create VM Helper
def create_vm(
    resource_group: str,
    vm_name: str,
    location: str = "eastus",
    vm_size: str = "Standard_B1s",
    admin_username: str = "azureuser",
    admin_password: str = None,
    image_publisher: str = "Canonical",
    image_offer: str = "0001-com-ubuntu-server-jammy",
    image_sku: str = "22_04-lts-gen2",
):
    print(f"Creating VM: {vm_name}...")
    
    vnet_name = f"{vm_name}-vnet"
    subnet_name = f"{vm_name}-subnet"
    ip_name = f"{vm_name}-ip"
    nic_name = f"{vm_name}-nic"
    nsg_name = f"{vm_name}-nsg"
    
    print("  Creating VNet...")
    vnet = network_client.virtual_networks.begin_create_or_update(
        resource_group, vnet_name,
        {
            "location": location,
            "address_space": {"address_prefixes": ["10.0.0.0/16"]}
        }
    ).result()
    
    print("  Creating Subnet...")
    subnet = network_client.subnets.begin_create_or_update(
        resource_group, vnet_name, subnet_name,
        {"address_prefix": "10.0.0.0/24"}
    ).result()
    
    print("  Creating Public IP...")
    public_ip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group, ip_name,
        {
            "location": location,
            "sku": {"name": "Standard"},
            "public_ip_allocation_method": "Static"
        }
    ).result()
    
    print("  Creating NSG...")
    nsg = network_client.network_security_groups.begin_create_or_update(
        resource_group, nsg_name,
        {
            "location": location,
            "security_rules": [
                {
                    "name": "SSH",
                    "protocol": "Tcp",
                    "source_port_range": "*",
                    "destination_port_range": "22",
                    "source_address_prefix": "*",
                    "destination_address_prefix": "*",
                    "access": "Allow",
                    "priority": 100,
                    "direction": "Inbound"
                }
            ]
        }
    ).result()
    
    print("  Creating NIC...")
    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group, nic_name,
        {
            "location": location,
            "ip_configurations": [{
                "name": "ipconfig1",
                "subnet": {"id": subnet.id},
                "public_ip_address": {"id": public_ip.id}
            }],
            "network_security_group": {"id": nsg.id}
        }
    ).result()
    
    print("  Creating VM...")
    vm_params = {
        "location": location,
        "hardware_profile": {"vm_size": vm_size},
        "storage_profile": {
            "image_reference": {
                "publisher": image_publisher,
                "offer": image_offer,
                "sku": image_sku,
                "version": "latest"
            },
            "os_disk": {
                "create_option": "FromImage",
                "managed_disk": {"storage_account_type": "Standard_LRS"}
            }
        },
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": admin_username,
        },
        "network_profile": {
            "network_interfaces": [{"id": nic.id}]
        }
    }
    
    if admin_password:
        vm_params["os_profile"]["admin_password"] = admin_password
        vm_params["os_profile"]["linux_configuration"] = {
            "disable_password_authentication": False
        }
    else:
        vm_params["os_profile"]["linux_configuration"] = {
            "disable_password_authentication": True,
            "ssh": {
                "public_keys": [{
                    "path": f"/home/{admin_username}/.ssh/authorized_keys",
                    "key_data": "ssh-rsa AAAA... your-ssh-public-key"
                }]
            }
        }
    
    vm = compute_client.virtual_machines.begin_create_or_update(
        resource_group, vm_name, vm_params
    ).result()
    
    public_ip = network_client.public_ip_addresses.get(resource_group, ip_name)
    print(f"\nVM created successfully!")
    print(f"  Name: {vm.name}")
    print(f"  Public IP: {public_ip.ip_address}")
    print(f"  SSH: ssh {admin_username}@{public_ip.ip_address}")
    
    return vm, public_ip.ip_address

#%% Delete Resource Group
def delete_resource_group(name: str):
    print(f"Deleting resource group: {name}...")
    poller = resource_client.resource_groups.begin_delete(name)
    poller.result()
    print(f"Resource group {name} deleted.")

#%% Show All Resources Summary
def show_summary():
    if not SUBSCRIPTION_ID:
        print("No subscription available!")
        return
    list_resource_groups()
    list_vms()
    list_vnets()
    list_public_ips()
    list_nsgs()

#%% Interactive Usage Examples
if __name__ == "__main__":
    print("\n" + "="*60)
    print("Azure Management Script Ready")
    print("="*60)
    print("""
Usage Examples:
    show_summary()                      # Show all resources
    list_vms()                          # List all VMs
    list_resource_groups()              # List resource groups
    
    create_resource_group("my-rg")      # Create resource group
    create_vm("my-rg", "my-vm",         # Create VM
              admin_password="P@ssw0rd123!")
    
    start_vm("my-rg", "my-vm")          # Start VM
    stop_vm("my-rg", "my-vm")           # Stop/deallocate VM
    restart_vm("my-rg", "my-vm")        # Restart VM
    
    get_vm_status("my-rg", "my-vm")     # Get VM details
    delete_resource_group("my-rg")      # Delete resource group
    """)
