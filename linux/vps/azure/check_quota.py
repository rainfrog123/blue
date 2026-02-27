#%% Imports and Setup
import os
import sys
import json
from pathlib import Path

# Find blue root (contains cred.json) and add to path for imports
_file = Path(__file__).resolve()
BLUE_ROOT = None
for _parent in _file.parents:
    if (_parent / "cred.json").exists():
        BLUE_ROOT = _parent
        sys.path.insert(0, str(_parent / "linux" / "extra"))
        break

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential, InteractiveBrowserCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.subscription import SubscriptionClient
except ImportError:
    print("Installing Azure SDK packages...")
    os.system("pip install --break-system-packages azure-identity azure-mgmt-compute azure-mgmt-subscription")
    from azure.identity import ClientSecretCredential, DefaultAzureCredential, InteractiveBrowserCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.subscription import SubscriptionClient

#%% Load or Create Azure Credentials
def get_azure_creds():
    """Get Azure credentials from cred.json, env vars, or prompt user."""
    
    # Try cred.json first
    if BLUE_ROOT:
        cred_path = BLUE_ROOT / "cred.json"
        if cred_path.exists():
            with open(cred_path) as f:
                creds = json.load(f)
                if "azure" in creds:
                    return creds["azure"]
    
    # Try environment variables
    if all(os.environ.get(k) for k in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]):
        return {
            "client_id": os.environ["AZURE_CLIENT_ID"],
            "tenant_id": os.environ["AZURE_TENANT_ID"],
            "client_secret": os.environ["AZURE_CLIENT_SECRET"],
            "subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID")
        }
    
    # Prompt user
    print("\n" + "="*60)
    print("Azure credentials not found. Please enter them:")
    print("(You can create a service principal with: az ad sp create-for-rbac)")
    print("="*60)
    
    client_id = input("Client ID (appId): ").strip()
    tenant_id = input("Tenant ID: ").strip()
    client_secret = input("Client Secret (password): ").strip()
    subscription_id = input("Subscription ID [79c81b4b-ee78-49de-9cba-af5f987e6b38]: ").strip()
    
    if not subscription_id:
        subscription_id = "79c81b4b-ee78-49de-9cba-af5f987e6b38"
    
    creds = {
        "client_id": client_id,
        "tenant_id": tenant_id,
        "client_secret": client_secret,
        "subscription_id": subscription_id
    }
    
    # Offer to save to cred.json
    if BLUE_ROOT:
        save = input("\nSave to cred.json? [y/N]: ").strip().lower()
        if save == 'y':
            cred_path = BLUE_ROOT / "cred.json"
            with open(cred_path) as f:
                all_creds = json.load(f)
            all_creds["azure"] = creds
            with open(cred_path, 'w') as f:
                json.dump(all_creds, f, indent=2)
            print(f"Saved to {cred_path}")
    
    return creds

#%% Initialize
creds = get_azure_creds()

CLIENT_ID = creds["client_id"]
TENANT_ID = creds["tenant_id"]
CLIENT_SECRET = creds["client_secret"]
SUBSCRIPTION_ID = creds.get("subscription_id", "79c81b4b-ee78-49de-9cba-af5f987e6b38")

credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)

print(f"\nAuthenticated with Azure (Tenant: {TENANT_ID[:8]}...)")
print(f"Using subscription: {SUBSCRIPTION_ID}")

#%% Initialize Compute Client
compute_client = ComputeManagementClient(credential, SUBSCRIPTION_ID)

#%% Check Quota for Location
def check_quota(location: str = "japaneast", filter_cores: bool = True):
    """Check compute quota/usage for a specific location."""
    print(f"\n{'='*72}")
    print(f"Compute Quota for: {location}")
    print(f"{'='*72}")
    
    try:
        usages = list(compute_client.usage.list(location))
        
        if filter_cores:
            usages = [u for u in usages if "core" in u.name.localized_value.lower() 
                      or "cpu" in u.name.localized_value.lower()
                      or "vcpu" in u.name.localized_value.lower()]
        
        print(f"\n{'Resource':<45} {'Used':>8} {'Limit':>8} {'Avail':>8}")
        print("-" * 72)
        
        for usage in sorted(usages, key=lambda x: x.name.localized_value):
            name = usage.name.localized_value
            current = usage.current_value
            limit = usage.limit
            available = limit - current
            
            status = ""
            if "lowpriority" in name.lower().replace(" ", "").replace("-", ""):
                status = " ← SPOT VMs"
            elif available < 16:
                status = " ⚠️"
            
            print(f"{name:<45} {current:>8} {limit:>8} {available:>8}{status}")
        
        return usages
    except Exception as e:
        print(f"Error: {e}")
        return []

#%% Check LowPriority/Spot Quota Specifically
def check_spot_quota(location: str = "japaneast", required_cores: int = 16):
    """Check specifically if you have enough Spot/LowPriority quota."""
    print(f"\n{'='*72}")
    print(f"Spot VM (LowPriority) Quota Check - {location}")
    print(f"{'='*72}")
    
    try:
        usages = list(compute_client.usage.list(location))
        
        spot_quota = None
        for usage in usages:
            name = usage.name.localized_value.lower().replace(" ", "").replace("-", "")
            if "lowpriority" in name:
                spot_quota = usage
                break
        
        if not spot_quota:
            print("❌ LowPriorityCores quota not found!")
            return None
        
        name = spot_quota.name.localized_value
        current = spot_quota.current_value
        limit = spot_quota.limit
        available = limit - current
        
        print(f"\n  Resource:        {name}")
        print(f"  Current Usage:   {current} cores")
        print(f"  Quota Limit:     {limit} cores")
        print(f"  Available:       {available} cores")
        print(f"  Required:        {required_cores} cores")
        
        print(f"\n  " + "-" * 50)
        
        if available >= required_cores:
            print(f"  ✅ SUFFICIENT QUOTA")
            print(f"     You can deploy a VM with {required_cores} cores.")
        else:
            print(f"  ❌ INSUFFICIENT QUOTA")
            print(f"     You need {required_cores} cores but only have {available} available.")
            print(f"\n  📝 TO FIX THIS:")
            print(f"     1. Request quota increase to at least {required_cores} (recommend {required_cores + 4})")
            print(f"     2. Use the Azure Portal link from your error message")
            print(f"     3. Or choose a smaller VM size (e.g., D2as_v7 with 2 cores)")
        
        return {
            "name": spot_quota.name.localized_value,
            "current": current,
            "limit": limit,
            "available": available,
            "sufficient": available >= required_cores
        }
    except Exception as e:
        print(f"Error: {e}")
        return None

#%% List Available VM Sizes
def list_vm_sizes(location: str = "japaneast", filter_pattern: str = None):
    """List available VM sizes in a location."""
    print(f"\n{'='*72}")
    print(f"Available VM Sizes in: {location}")
    print(f"{'='*72}")
    
    try:
        sizes = list(compute_client.virtual_machine_sizes.list(location))
        
        if filter_pattern:
            filter_lower = filter_pattern.lower()
            sizes = [s for s in sizes if filter_lower in s.name.lower()]
        
        print(f"\n{'Name':<30} {'Cores':>6} {'RAM (MB)':>10} {'Disk (GB)':>10}")
        print("-" * 60)
        
        for size in sorted(sizes, key=lambda x: (x.number_of_cores, x.memory_in_mb)):
            print(f"{size.name:<30} {size.number_of_cores:>6} {size.memory_in_mb:>10} {size.resource_disk_size_in_mb // 1024:>10}")
        
        return sizes
    except Exception as e:
        print(f"Error: {e}")
        return []

#%% Check All Regions Quota
def check_all_regions_spot_quota():
    """Check Spot quota across multiple regions."""
    regions = ["japaneast", "japanwest", "eastus", "westus", "eastus2", 
               "westeurope", "northeurope", "southeastasia", "australiaeast"]
    
    print(f"\n{'='*72}")
    print("Spot VM (LowPriority) Quota Across Regions")
    print(f"{'='*72}")
    print(f"\n{'Region':<20} {'Used':>8} {'Limit':>8} {'Available':>8}")
    print("-" * 50)
    
    results = []
    for region in regions:
        try:
            usages = list(compute_client.usage.list(region))
            for usage in usages:
                if "lowpriority" in usage.name.localized_value.lower().replace(" ", ""):
                    current = usage.current_value
                    limit = usage.limit
                    available = limit - current
                    status = "✓" if available >= 16 else "⚠️"
                    print(f"{region:<20} {current:>8} {limit:>8} {available:>8} {status}")
                    results.append({"region": region, "current": current, "limit": limit, "available": available})
                    break
        except Exception as e:
            print(f"{region:<20} {'Error':>8}")
    
    return results

#%% Interactive Usage
if __name__ == "__main__":
    print("\n" + "="*72)
    print("Azure Quota Check Ready")
    print("="*72)
    print("""
Usage Examples:
    check_quota("japaneast")              # All compute quotas for region
    check_quota("japaneast", False)       # All quotas (not just cores)
    
    check_spot_quota("japaneast", 16)     # Check if 16 Spot cores available
    check_spot_quota("eastus", 4)         # Check if 4 Spot cores in East US
    
    check_all_regions_spot_quota()        # Compare Spot quota across regions
    
    list_vm_sizes("japaneast")            # All VM sizes
    list_vm_sizes("japaneast", "D16")     # Filter by pattern
    """)
    
    # Run the check for Japan East with 16 cores requirement
    check_spot_quota("japaneast", 16)
