# %% [markdown]
# # Alibaba Cloud VPS API Testing
# Testing ECS (Elastic Compute Service) API operations

# %% Imports and Configuration
import sys
from datetime import datetime
from pathlib import Path

# Add cred_loader to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "extra" / "config"))
from cred_loader import get_alibaba

from alibabacloud_ecs20140526 import models as ecs_models

# pip install alibabacloud_ecs20140526
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models

# Load credentials via cred_loader
_alibaba = get_alibaba()
ACCESS_KEY_ID = _alibaba["access_key_id"]
ACCESS_KEY_SECRET = _alibaba["access_key_secret"]
REGION_ID = "cn-hongkong"  # Change to your region


# %% Initialize Client
def create_client(region_id: str = REGION_ID) -> EcsClient:
    """Create Alibaba Cloud ECS client"""
    config = open_api_models.Config(
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET,
    )
    config.endpoint = f"ecs.{region_id}.aliyuncs.com"
    return EcsClient(config)


client = create_client()
print(f"Client initialized for region: {REGION_ID}")


# %% List All Regions
def list_regions():
    """List all available regions"""
    request = ecs_models.DescribeRegionsRequest()
    response = client.describe_regions(request)
    regions = response.body.regions.region

    print(f"{'Region ID':<25} {'Local Name':<20} {'Endpoint'}")
    print("-" * 80)
    for region in regions:
        print(f"{region.region_id:<25} {region.local_name:<20} {region.region_endpoint}")

    return regions


regions = list_regions()


# %% List Instances
def list_instances(region_id: str = REGION_ID):
    """List all ECS instances in a region"""
    request = ecs_models.DescribeInstancesRequest(region_id=region_id, page_size=100)
    response = client.describe_instances(request)
    instances = response.body.instances.instance

    print(f"\n{'Instance ID':<25} {'Name':<20} {'Status':<12} {'IP Address':<16} {'Type'}")
    print("-" * 100)

    for inst in instances:
        ips = inst.public_ip_address.ip_address
        public_ip = ips[0] if ips else "N/A"
        print(
            f"{inst.instance_id:<25} {inst.instance_name:<20} "
            f"{inst.status:<12} {public_ip:<16} {inst.instance_type}"
        )

    return instances


instances = list_instances()


# %% Get Instance Details
def get_instance_detail(instance_id: str, region_id: str = REGION_ID):
    """Get detailed information about a specific instance"""
    request = ecs_models.DescribeInstanceAttributeRequest(instance_id=instance_id)
    response = client.describe_instance_attribute(request)
    inst = response.body

    print(f"\n=== Instance Details: {instance_id} ===")
    print(f"Name: {inst.instance_name}")
    print(f"Status: {inst.status}")
    print(f"Type: {inst.instance_type}")
    print(f"CPU: {inst.cpu} cores")
    print(f"Memory: {inst.memory} MB")
    print(f"OS: {inst.osname}")
    print(f"Zone: {inst.zone_id}")
    print(f"Created: {inst.creation_time}")
    print(f"Public IPs: {inst.public_ip_address.ip_address}")
    print(f"Private IPs: {inst.vpc_attributes.private_ip_address.ip_address}")

    return inst


# Uncomment to test with a specific instance
# detail = get_instance_detail('i-xxxxxxxxxx')


# %% Start Instance
def start_instance(instance_id: str):
    """Start a stopped ECS instance"""
    request = ecs_models.StartInstanceRequest(instance_id=instance_id)
    response = client.start_instance(request)
    print(f"Start request sent for {instance_id}")
    print(f"Request ID: {response.body.request_id}")
    return response


# Uncomment to start an instance
# start_instance('i-xxxxxxxxxx')


# %% Stop Instance
def stop_instance(instance_id: str, force: bool = False):
    """Stop a running ECS instance"""
    request = ecs_models.StopInstanceRequest(instance_id=instance_id, force_stop=force)
    response = client.stop_instance(request)
    print(f"Stop request sent for {instance_id}")
    print(f"Request ID: {response.body.request_id}")
    return response


# Uncomment to stop an instance
# stop_instance('i-xxxxxxxxxx')


# %% Reboot Instance
def reboot_instance(instance_id: str, force: bool = False):
    """Reboot an ECS instance"""
    request = ecs_models.RebootInstanceRequest(
        instance_id=instance_id, force_stop=force
    )
    response = client.reboot_instance(request)
    print(f"Reboot request sent for {instance_id}")
    print(f"Request ID: {response.body.request_id}")
    return response


# Uncomment to reboot an instance
# reboot_instance('i-xxxxxxxxxx')


# %% List Available Instance Types
def list_instance_types(region_id: str = REGION_ID):
    """List available instance types in a region"""
    request = ecs_models.DescribeInstanceTypesRequest()
    response = client.describe_instance_types(request)
    types = response.body.instance_types.instance_type

    # Filter to show common types
    common_types = [t for t in types if t.instance_type_family.startswith("ecs.")][:20]

    print(f"\n{'Type ID':<25} {'vCPU':<6} {'Memory (GB)':<12} {'Family'}")
    print("-" * 60)
    for t in common_types:
        print(
            f"{t.instance_type_id:<25} {t.cpu_core_count:<6} "
            f"{t.memory_size:<12} {t.instance_type_family}"
        )

    return types


instance_types = list_instance_types()


# %% List Security Groups
def list_security_groups(region_id: str = REGION_ID):
    """List security groups in a region"""
    request = ecs_models.DescribeSecurityGroupsRequest(region_id=region_id)
    response = client.describe_security_groups(request)
    groups = response.body.security_groups.security_group

    print(f"\n{'Security Group ID':<25} {'Name':<30} {'VPC ID'}")
    print("-" * 80)
    for sg in groups:
        vpc = sg.vpc_id or "Classic"
        print(f"{sg.security_group_id:<25} {sg.security_group_name:<30} {vpc}")

    return groups


# security_groups = list_security_groups()


# %% Get Account Balance
def get_account_balance():
    """Get account balance (requires BSS API)"""
    # pip install alibabacloud_bssopenapi20171214
    try:
        from alibabacloud_bssopenapi20171214 import models as bss_models
        from alibabacloud_bssopenapi20171214.client import Client as BssClient

        config = open_api_models.Config(
            access_key_id=ACCESS_KEY_ID,
            access_key_secret=ACCESS_KEY_SECRET,
        )
        config.endpoint = "business.aliyuncs.com"
        bss_client = BssClient(config)

        request = bss_models.QueryAccountBalanceRequest()
        response = bss_client.query_account_balance(request)
        balance = response.body.data

        print("\n=== Account Balance ===")
        print(f"Available: {balance.available_amount} {balance.currency}")
        print(f"Credit: {balance.credit_amount} {balance.currency}")

        return balance
    except ImportError:
        print("Install alibabacloud_bssopenapi20171214 for balance queries")
        return None


balance = get_account_balance()


# %% Quick Status Check
def quick_status():
    """Quick status check of all instances"""
    print(f"\n{'='*50}")
    print(f"Alibaba Cloud ECS Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Region: {REGION_ID}")
    print(f"{'='*50}")

    instances = list_instances()

    running = sum(1 for i in instances if i.status == "Running")
    stopped = sum(1 for i in instances if i.status == "Stopped")

    print(f"\nSummary: {len(instances)} total, {running} running, {stopped} stopped")


quick_status()
