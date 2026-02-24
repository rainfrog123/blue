# %% Rotate Backup - Create Image and Terminate Instance
"""
Create a backup image from current instance, then terminate it.

This script:
1. Creates a snapshot from the instance's system disk
2. Waits for snapshot completion
3. Creates a custom image from the snapshot
4. Waits for image to be available
5. Deletes all OLD snapshots (keeps only the new one)
6. Deletes all OLD images (keeps only the new one)
7. Stops and deletes the instance

Final state: Only ONE snapshot and ONE image remain (for later rebuild).

Usage:
    Run rotate_and_terminate() to execute the full workflow.
"""
import time
from datetime import datetime
from aliyun_client import ecs_client, ecs_models, REGION_ID, print_header
from ecs_operations import (
    get_instance, get_system_disk, list_instances, list_disks,
    list_snapshots, list_images,
    create_snapshot, wait_for_snapshot, delete_snapshot,
    create_image_from_snapshot, wait_for_image, delete_image
)

print_header("ROTATE BACKUP & TERMINATE")


# %% Display Current State
def show_current_state():
    """Display current instance, snapshots, and images."""
    print(f"\n{'='*60}")
    print("CURRENT STATE")
    print(f"{'='*60}")
    
    # Instance
    instance = get_instance()
    if instance:
        print(f"\nInstance:")
        print(f"  ID:     {instance.instance_id}")
        print(f"  Name:   {instance.instance_name}")
        print(f"  Status: {instance.status}")
        
        # System disk
        disk = get_system_disk(instance.instance_id)
        if disk:
            print(f"\nSystem Disk:")
            print(f"  ID:   {disk.disk_id}")
            print(f"  Size: {disk.size} GB")
    else:
        print("\nInstance: None")
    
    # Snapshots
    snapshots = list_snapshots(verbose=False)
    print(f"\nSnapshots ({len(snapshots)}):")
    for snap in snapshots:
        print(f"  - {snap.snapshot_id}: {snap.snapshot_name or '(unnamed)'}")
        print(f"    Created: {snap.creation_time}")
    
    # Images
    images = list_images("self", verbose=False)
    print(f"\nCustom Images ({len(images)}):")
    for img in images:
        print(f"  - {img.image_id}: {img.image_name}")
        print(f"    Created: {img.creation_time}")
    
    print(f"{'='*60}")
    
    return instance, snapshots, images


# %% Stop Instance
def stop_instance(instance_id: str) -> bool:
    """Stop the instance and wait for stopped status."""
    print(f"  Stopping instance {instance_id}...")
    
    # Check current status
    attr_request = ecs_models.DescribeInstanceAttributeRequest(instance_id=instance_id)
    attr_response = ecs_client.describe_instance_attribute(attr_request)
    
    if attr_response.body.status == "Stopped":
        print(f"  Instance already stopped")
        return True
    
    stop_request = ecs_models.StopInstanceRequest(instance_id=instance_id, force_stop=True)
    ecs_client.stop_instance(stop_request)
    
    # Wait for stopped status (2 min timeout)
    for i in range(24):
        time.sleep(5)
        attr_response = ecs_client.describe_instance_attribute(attr_request)
        status = attr_response.body.status
        print(f"    Status: {status}")
        if status == "Stopped":
            return True
    
    print(f"  [ERROR] Timeout waiting for stop")
    return False


# %% Delete Instance
def delete_instance(instance_id: str) -> bool:
    """Delete the instance."""
    print(f"  Deleting instance {instance_id}...")
    
    try:
        request = ecs_models.DeleteInstanceRequest(
            instance_id=instance_id,
            force=True,
            terminate_subscription=True,
        )
        ecs_client.delete_instance(request)
        print(f"  Instance deleted")
        return True
    except Exception as e:
        print(f"  [ERROR] Delete failed: {e}")
        return False


# Show initial state
instance, old_snapshots, old_images = show_current_state()


# %% Main Function: Rotate and Terminate
def rotate_and_terminate():
    """
    Create backup from instance, then terminate instance.
    
    Steps:
    1. Create snapshot from system disk
    2. Wait for snapshot completion
    3. Create image from snapshot
    4. Wait for image availability
    5. Delete old snapshots (keep new)
    6. Delete old images (keep new)
    7. Stop and delete instance
    
    Returns:
        dict with snapshot_id and image_id, or None if failed
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"\n{'#'*60}")
    print(f"# ROTATE BACKUP & TERMINATE INSTANCE")
    print(f"{'#'*60}")
    print(f"Timestamp: {timestamp}")
    
    # Get current instance
    instance = get_instance()
    if not instance:
        print("[ERROR] No instance found")
        return None
    
    instance_id = instance.instance_id
    instance_name = instance.instance_name
    
    print(f"\nInstance: {instance_id} ({instance_name})")
    
    # Get system disk
    disk = get_system_disk(instance_id)
    if not disk:
        print("[ERROR] No system disk found")
        return None
    
    print(f"System Disk: {disk.disk_id} ({disk.size} GB)")
    
    # Get old resources to delete later
    old_snapshots = list_snapshots(verbose=False)
    old_images = list_images("self", verbose=False)
    
    print(f"\nOld snapshots to delete: {len(old_snapshots)}")
    print(f"Old images to delete: {len(old_images)}")
    
    # Backup names
    snap_name = f"backup_{timestamp}"
    img_name = f"backup_{timestamp}"
    description = f"Backup from {instance_id} ({instance_name}) at {timestamp}"
    
    # =========================================================================
    # Step 1: Create new snapshot
    # =========================================================================
    print(f"\n[1/7] Creating snapshot from system disk...")
    new_snapshot_id = create_snapshot(disk.disk_id, snap_name, description)
    if not new_snapshot_id:
        print("[ERROR] Failed to create snapshot")
        return None
    
    # =========================================================================
    # Step 2: Wait for snapshot (30 min timeout for large disks)
    # =========================================================================
    print(f"\n[2/7] Waiting for snapshot to complete...")
    if not wait_for_snapshot(new_snapshot_id, timeout=1800):
        print("[ERROR] Snapshot failed")
        return None
    print(f"  Snapshot ready: {new_snapshot_id}")
    
    # =========================================================================
    # Step 3: Create image from snapshot
    # =========================================================================
    print(f"\n[3/7] Creating image from snapshot...")
    new_image_id = create_image_from_snapshot(new_snapshot_id, img_name, description)
    if not new_image_id:
        print("[ERROR] Failed to create image")
        return None
    
    # =========================================================================
    # Step 4: Wait for image (30 min timeout for large disks)
    # =========================================================================
    print(f"\n[4/7] Waiting for image to be available...")
    if not wait_for_image(new_image_id, timeout=1800):
        print("[ERROR] Image creation failed")
        return None
    print(f"  Image ready: {new_image_id}")
    
    # =========================================================================
    # Step 5: Delete old snapshots
    # =========================================================================
    print(f"\n[5/7] Deleting old snapshots...")
    for snap in old_snapshots:
        if snap.snapshot_id != new_snapshot_id:
            try:
                delete_snapshot(snap.snapshot_id, force=True, verbose=False)
                print(f"  Deleted: {snap.snapshot_id}")
            except Exception as e:
                print(f"  [WARN] Failed to delete {snap.snapshot_id}: {e}")
    
    # =========================================================================
    # Step 6: Delete old images
    # =========================================================================
    print(f"\n[6/7] Deleting old images...")
    for img in old_images:
        if img.image_id != new_image_id:
            try:
                delete_image(img.image_id, force=True, verbose=False)
                print(f"  Deleted: {img.image_id}")
            except Exception as e:
                print(f"  [WARN] Failed to delete {img.image_id}: {e}")
    
    # =========================================================================
    # Step 7: Stop and delete instance
    # =========================================================================
    print(f"\n[7/7] Terminating instance...")
    
    # Stop first
    if not stop_instance(instance_id):
        print("[ERROR] Failed to stop instance")
        return {"snapshot_id": new_snapshot_id, "image_id": new_image_id}
    
    # Small delay then delete
    time.sleep(2)
    
    if not delete_instance(instance_id):
        print("[ERROR] Failed to delete instance")
        return {"snapshot_id": new_snapshot_id, "image_id": new_image_id}
    
    # =========================================================================
    # Done
    # =========================================================================
    print(f"\n{'='*60}")
    print("ROTATE & TERMINATE COMPLETE")
    print(f"{'='*60}")
    print(f"New Snapshot: {new_snapshot_id}")
    print(f"New Image:    {new_image_id}")
    print(f"Instance:     DELETED ({instance_id})")
    print(f"\nFinal state:")
    print(f"  - 1 snapshot (for rebuild)")
    print(f"  - 1 image (for rebuild)")
    print(f"  - 0 instances")
    
    return {"snapshot_id": new_snapshot_id, "image_id": new_image_id}


print(f"\n[OK] Function defined:")
print(f"  rotate_and_terminate()  - Create backup, delete old, terminate instance")


# %% EXECUTE - Rotate and Terminate
rotate_and_terminate()


# %% Verify Final State
show_current_state()
