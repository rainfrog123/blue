# %% Setup
"""Delete ECS instances."""
import time
from client import ecs_client, ecs_models, REGION_ID, print_header
from ecs_api import list_instances, list_disks

print_header("DELETE INSTANCE")


# %% Show Current ECS Instance
instances = list_instances()

if not instances:
    print("No instances found in this region.")
    instance = None
else:
    instance = instances[0]
    ips = instance.public_ip_address.ip_address if instance.public_ip_address else []
    public_ip = ips[0] if ips else "N/A"
    
    private_ips = []
    if instance.vpc_attributes and instance.vpc_attributes.private_ip_address:
        private_ips = instance.vpc_attributes.private_ip_address.ip_address
    private_ip = private_ips[0] if private_ips else "N/A"
    
    print(f"\n{'='*60}")
    print(f"TARGET INSTANCE")
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
    print(f"Charge Type:    {instance.instance_charge_type}")
    print(f"{'='*60}")


# %% Show Attached Disks
if instance:
    disks = list_disks(instance_id=instance.instance_id)
    
    print(f"\nDISK AUTO-DELETE STATUS:")
    print("-" * 60)
    for disk in disks:
        auto_del = "auto-delete" if disk.delete_with_instance else "KEEP"
        print(f"  {disk.disk_id}: {disk.size}GB {disk.type} -> {auto_del}")
else:
    disks = []


# %% Show Security Groups
if instance:
    sg_ids = instance.security_group_ids.security_group_id
    print(f"\nSECURITY GROUPS ({len(sg_ids)}):")
    print("-" * 60)
    for sg_id in sg_ids:
        print(f"  {sg_id}")


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


# %% Full Release (Stop + Delete)
def release_all():
    """
    Release the instance and all resources.
    System disk is auto-deleted with instance.
    """
    if not instance:
        print("No instance found")
        return
    
    print(f"\n{'#'*60}")
    print(f"# RELEASE INSTANCE")
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


print(f"\nCurrent status: {instance.status if instance else 'N/A'}")
print("Run release_all() to stop and delete the instance")


# %% EXECUTE DELETE
# release_all()


# %% Check All Existing Instances
list_instances()
