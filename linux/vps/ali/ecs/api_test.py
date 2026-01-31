# %% [markdown]
# # Alibaba Cloud VPS API Testing
# Testing ECS (Elastic Compute Service) API operations

# %% Setup
"""API testing for Alibaba Cloud ECS."""
from client import ecs_client, ecs_models, REGION_ID, print_header
from ecs_api import list_instances, list_images, list_disks, list_snapshots

print_header("API TEST")


# %% List All Regions
def list_regions():
    """List all available regions"""
    request = ecs_models.DescribeRegionsRequest()
    response = ecs_client.describe_regions(request)
    regions = response.body.regions.region

    print(f"{'Region ID':<25} {'Local Name':<20} {'Endpoint'}")
    print("-" * 80)
    for region in regions:
        print(f"{region.region_id:<25} {region.local_name:<20} {region.region_endpoint}")

    return regions


regions = list_regions()


# %% List Instances
instances = list_instances()


# %% List Instance Types
def list_instance_types(cpu_min: int = None, mem_min: int = None, family: str = None):
    """
    List available instance types
    
    Args:
        cpu_min: Minimum CPU cores
        mem_min: Minimum memory in GB
        family: Instance family (e.g., "ecs.g7", "ecs.c7")
    """
    request = ecs_models.DescribeInstanceTypesRequest()
    if family:
        request.instance_type_family = family
        
    response = ecs_client.describe_instance_types(request)
    types = response.body.instance_types.instance_type

    # Filter
    filtered = types
    if cpu_min:
        filtered = [t for t in filtered if t.cpu_core_count >= cpu_min]
    if mem_min:
        filtered = [t for t in filtered if t.memory_size >= mem_min]

    print(f"\n{'Type':<25} {'CPU':<6} {'Memory':<10} {'GPU'}")
    print("-" * 60)
    for t in filtered[:20]:  # Limit output
        gpu = f"{t.gpuamount}x {t.gpuspec}" if t.gpuamount else "-"
        print(f"{t.instance_type_id:<25} {t.cpu_core_count:<6} {t.memory_size:<10.1f} {gpu}")

    print(f"\nShowing {min(20, len(filtered))} of {len(filtered)} types")
    return filtered


# Example: 4+ CPU, 8+ GB RAM
# types = list_instance_types(cpu_min=4, mem_min=8)


# %% List Images
custom_images = list_images("self")


# %% List Disks
disks = list_disks()


# %% List Snapshots
snapshots = list_snapshots()


# %% Get Pricing (Spot vs On-Demand)
def get_spot_prices(instance_type: str = "ecs.g7a.xlarge"):
    """Get spot instance prices"""
    request = ecs_models.DescribeSpotPriceHistoryRequest(
        region_id=REGION_ID,
        instance_type=instance_type,
        network_type="vpc"
    )
    response = ecs_client.describe_spot_price_history(request)
    
    # Handle None response
    prices = []
    if response.body and response.body.spot_prices and response.body.spot_prices.spot_price_type:
        prices = response.body.spot_prices.spot_price_type

    print(f"\n{'='*80}")
    print(f"Spot Prices for {instance_type} in {REGION_ID}")
    print(f"{'='*80}")

    if not prices:
        print("No price data available")
        return []

    for p in prices[:10]:  # Show recent prices
        print(f"  {p.timestamp}: ¥{p.spot_price}/hour (Zone: {p.zone_id})")

    return prices


# get_spot_prices("ecs.g7a.xlarge")


# %% Summary
print(f"\n{'='*80}")
print("API TEST SUMMARY")
print(f"{'='*80}")
print(f"Region:    {REGION_ID}")
print(f"Instances: {len(instances)}")
print(f"Images:    {len(custom_images)}")
print(f"Disks:     {len(disks)}")
print(f"Snapshots: {len(snapshots)}")
print(f"{'='*80}")
