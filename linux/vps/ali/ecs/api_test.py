# %% [markdown]
# # Alibaba Cloud VPS API Testing
# Testing ECS (Elastic Compute Service) API operations

# %% Setup
"""API testing for Alibaba Cloud ECS."""
from datetime import datetime
from client import ecs_client, ecs_models, REGION_ID, print_header

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
def list_instances(status: str = None):
    """
    List ECS instances
    
    Args:
        status: Filter by status (Running, Stopped, etc.) or None for all
    """
    request = ecs_models.DescribeInstancesRequest(
        region_id=REGION_ID,
        page_size=100
    )
    if status:
        request.status = status
        
    response = ecs_client.describe_instances(request)
    
    # Handle None response
    instances = []
    if response.body and response.body.instances and response.body.instances.instance:
        instances = response.body.instances.instance

    print(f"\n{'='*80}")
    print(f"Instances in {REGION_ID}" + (f" (status: {status})" if status else ""))
    print(f"{'='*80}")

    if not instances:
        print("No instances found")
        return []

    for inst in instances:
        ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
        public_ip = ips[0] if ips else "N/A"
        print(f"\n{inst.instance_name}")
        print(f"  ID:       {inst.instance_id}")
        print(f"  Status:   {inst.status}")
        print(f"  Type:     {inst.instance_type}")
        print(f"  OS:       {inst.osname}")
        print(f"  Public:   {public_ip}")
        print(f"  Zone:     {inst.zone_id}")
        print(f"  Created:  {inst.creation_time}")

    print(f"\nTotal: {len(instances)} instance(s)")
    return instances


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
def list_images(owner: str = "self"):
    """
    List available images
    
    Args:
        owner: "self" (custom), "system", "others" (shared), "marketplace"
    """
    request = ecs_models.DescribeImagesRequest(
        region_id=REGION_ID,
        image_owner_alias=owner,
        page_size=50
    )
    response = ecs_client.describe_images(request)
    
    # Handle None response
    images = []
    if response.body and response.body.images and response.body.images.image:
        images = response.body.images.image

    print(f"\n{'='*80}")
    print(f"Images ({owner}) in {REGION_ID}")
    print(f"{'='*80}")

    if not images:
        print("No images found")
        return []

    for img in images:
        print(f"\n{img.image_name}")
        print(f"  ID:      {img.image_id}")
        print(f"  OS:      {img.osname}")
        print(f"  Size:    {img.size} GB")
        print(f"  Status:  {img.status}")
        print(f"  Created: {img.creation_time}")

    print(f"\nTotal: {len(images)} image(s)")
    return images


custom_images = list_images("self")


# %% List Disks
def list_disks(instance_id: str = None):
    """List cloud disks, optionally filtered by instance"""
    request = ecs_models.DescribeDisksRequest(
        region_id=REGION_ID,
        page_size=100
    )
    if instance_id:
        request.instance_id = instance_id
        
    response = ecs_client.describe_disks(request)
    
    # Handle None response
    disks = []
    if response.body and response.body.disks and response.body.disks.disk:
        disks = response.body.disks.disk

    print(f"\n{'='*80}")
    print(f"Disks in {REGION_ID}" + (f" (instance: {instance_id})" if instance_id else ""))
    print(f"{'='*80}")

    if not disks:
        print("No disks found")
        return []

    for disk in disks:
        print(f"\n{disk.disk_name or '(unnamed)'}")
        print(f"  ID:       {disk.disk_id}")
        print(f"  Type:     {disk.type} ({disk.category})")
        print(f"  Size:     {disk.size} GB")
        print(f"  Status:   {disk.status}")
        print(f"  Instance: {disk.instance_id or 'N/A'}")

    print(f"\nTotal: {len(disks)} disk(s)")
    return disks


disks = list_disks()


# %% List Snapshots
def list_snapshots():
    """List all snapshots"""
    request = ecs_models.DescribeSnapshotsRequest(
        region_id=REGION_ID,
        page_size=100
    )
    response = ecs_client.describe_snapshots(request)
    
    # Handle None response
    snapshots = []
    if response.body and response.body.snapshots and response.body.snapshots.snapshot:
        snapshots = response.body.snapshots.snapshot

    print(f"\n{'='*80}")
    print(f"Snapshots in {REGION_ID}")
    print(f"{'='*80}")

    if not snapshots:
        print("No snapshots found")
        return []

    for snap in snapshots:
        print(f"\n{snap.snapshot_name or '(unnamed)'}")
        print(f"  ID:       {snap.snapshot_id}")
        print(f"  Disk:     {snap.source_disk_id}")
        print(f"  Size:     {snap.source_disk_size} GB")
        print(f"  Status:   {snap.status}")
        print(f"  Progress: {snap.progress}")
        print(f"  Created:  {snap.creation_time}")

    print(f"\nTotal: {len(snapshots)} snapshot(s)")
    return snapshots


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
