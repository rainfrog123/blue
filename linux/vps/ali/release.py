# %% Show Current ECS Instance
import sys
import time
from pathlib import Path

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "extra" / "config"))
from cred_loader import get_alibaba

from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models

# Load credentials
_alibaba = get_alibaba()
ACCESS_KEY_ID = _alibaba["access_key_id"]
ACCESS_KEY_SECRET = _alibaba["access_key_secret"]
REGION_ID = "cn-hongkong"

# Create client
config = open_api_models.Config(
    access_key_id=ACCESS_KEY_ID,
    access_key_secret=ACCESS_KEY_SECRET,
)
config.endpoint = f"ecs.{REGION_ID}.aliyuncs.com"
ecs_client = EcsClient(config)

# Fetch the single instance
request = ecs_models.DescribeInstancesRequest(region_id=REGION_ID, page_size=100)
response = ecs_client.describe_instances(request)
instances = response.body.instances.instance

if not instances:
    print("No instances found in this region.")
    instance = None
else:
    instance = instances[0]
    ips = instance.public_ip_address.ip_address
    public_ip = ips[0] if ips else "N/A"
    
    private_ips = []
    if instance.vpc_attributes and instance.vpc_attributes.private_ip_address:
        private_ips = instance.vpc_attributes.private_ip_address.ip_address
    private_ip = private_ips[0] if private_ips else "N/A"
    
    print(f"{'='*60}")
    print(f"TARGET INSTANCE - Region: {REGION_ID}")
    print(f"{'='*60}")
    print(f"Name:           {instance.instance_name}")
    print(f"Instance ID:    {instance.instance_id}")
    print(f"Status:         {instance.status}")
    print(f"Type:           {instance.instance_type}")
    print(f"CPU/Memory:     {instance.cpu} vCPU / {instance.memory} MB")
    print(f"Public IP:      {public_ip}")
    print(f"Private IP:     {private_ip}")
    print(f"OS:             {instance.osname}")
    print(f"Zone:           {instance.zone_id}")
    print(f"Created:        {instance.creation_time}")
    print(f"Charge Type:    {instance.instance_charge_type}")
    print(f"{'='*60}")


# %% Show Attached Disks
if instance:
    disk_request = ecs_models.DescribeDisksRequest(
        region_id=REGION_ID, 
        instance_id=instance.instance_id
    )
    disk_response = ecs_client.describe_disks(disk_request)
    disks = disk_response.body.disks.disk
    
    print(f"\nATTACHED DISKS ({len(disks)}):")
    print("-" * 60)
    for disk in disks:
        auto_del = "auto-delete" if disk.delete_with_instance else "KEEP"
        print(f"  {disk.disk_id}")
        print(f"    Size:     {disk.size} GB")
        print(f"    Type:     {disk.type} ({disk.category})")
        print(f"    On Delete: {auto_del}")
else:
    disks = []
    print("No instance to check disks")


# %% Show Security Groups
if instance:
    sg_ids = instance.security_group_ids.security_group_id
    print(f"\nSECURITY GROUPS ({len(sg_ids)}):")
    print("-" * 60)
    for sg_id in sg_ids:
        print(f"  {sg_id}")
else:
    print("No instance to check security groups")


# %% Stop Instance
def stop_instance():
    """Stop the instance and wait"""
    if not instance:
        print("No instance to stop")
        return False
    
    inst_id = instance.instance_id
    
    # Check current status
    attr_request = ecs_models.DescribeInstanceAttributeRequest(instance_id=inst_id)
    attr_response = ecs_client.describe_instance_attribute(attr_request)
    
    if attr_response.body.status == "Stopped":
        print(f"Instance {inst_id} is already stopped")
        return True
    
    print(f"Stopping instance {inst_id}...")
    stop_request = ecs_models.StopInstanceRequest(instance_id=inst_id, force_stop=True)
    ecs_client.stop_instance(stop_request)
    
    # Wait for stopped status
    for i in range(24):  # 2 minutes timeout
        time.sleep(5)
        attr_response = ecs_client.describe_instance_attribute(attr_request)
        status = attr_response.body.status
        print(f"  Status: {status}")
        if status == "Stopped":
            print("Instance stopped successfully")
            return True
    
    print("Timeout waiting for instance to stop")
    return False


print(f"\nCurrent status: {instance.status if instance else 'N/A'}")
print("Run stop_instance() to stop")


# %% Delete Instance
def delete_instance():
    """Delete the instance"""
    if not instance:
        print("No instance to delete")
        return False
    
    inst_id = instance.instance_id
    print(f"Deleting instance {inst_id}...")
    
    try:
        request = ecs_models.DeleteInstanceRequest(
            instance_id=inst_id,
            force=True,
            terminate_subscription=True,
        )
        ecs_client.delete_instance(request)
        print(f"Instance {inst_id} deleted successfully")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


print(f"\nInstance ID: {instance.instance_id if instance else 'N/A'}")
print("Run delete_instance() to delete (must be stopped first)")


# %% Full Release (Stop + Delete)
def release_all(dry_run=True):
    """
    Release the instance and all resources.
    System disk is auto-deleted with instance.
    
    Args:
        dry_run: If True, only show what would happen
    """
    if not instance:
        print("No instance found")
        return
    
    print(f"\n{'#'*60}")
    print(f"# {'DRY RUN - ' if dry_run else ''}RELEASE INSTANCE")
    print(f"{'#'*60}")
    print(f"Instance: {instance.instance_name}")
    print(f"ID:       {instance.instance_id}")
    print(f"Status:   {instance.status}")
    print(f"\nDisks to be deleted with instance:")
    for disk in disks:
        if disk.delete_with_instance:
            print(f"  - {disk.disk_id} ({disk.size}GB {disk.type})")
    
    manual_disks = [d for d in disks if not d.delete_with_instance]
    if manual_disks:
        print(f"\nDisks that will REMAIN (manual delete needed):")
        for disk in manual_disks:
            print(f"  - {disk.disk_id} ({disk.size}GB {disk.type})")
    
    if dry_run:
        print(f"\n{'!'*60}")
        print("DRY RUN - No changes made")
        print("Run: release_all(dry_run=False) to actually delete")
        print(f"{'!'*60}")
        return
    
    # Step 1: Stop
    print(f"\n[1/2] Stopping instance...")
    if not stop_instance():
        print("Failed to stop. Aborting.")
        return
    
    # Step 2: Delete
    print(f"\n[2/2] Deleting instance...")
    time.sleep(2)
    if not delete_instance():
        print("Failed to delete.")
        return
    
    print(f"\n{'='*60}")
    print("RELEASE COMPLETE")
    print(f"{'='*60}")


# %% EXECUTE DELETE
release_all(dry_run=False)
