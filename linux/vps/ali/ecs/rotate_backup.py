# %% Rotate Backup - Automated Snapshot and Image Rotation
"""
Automated backup rotation for ECS instances.

This script implements a rotation strategy that:
1. Creates a new snapshot from the system disk
2. Waits for snapshot completion
3. Creates a new custom image from the snapshot
4. Optionally deletes old snapshots and images

Functions:
    create_backup()  - Create new backup, keep existing
    rotate_backup()  - Create new backup, delete old ones

Usage:
    Run create_backup() for safe incremental backups.
    Run rotate_backup() to maintain single backup (saves storage cost).
"""
from datetime import datetime
from aliyun_client import print_header
from ecs_operations import (
    get_instance, get_system_disk,
    list_snapshots, list_images,
    create_snapshot, wait_for_snapshot, delete_snapshot,
    create_image_from_snapshot, wait_for_image, delete_image
)

print_header("ROTATE BACKUP")


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


# Show current state
instance, old_snapshots, old_images = show_current_state()


# %% Backup Rotation Function
def rotate_backup():
    """
    Perform backup rotation:
    1. Create new snapshot from instance's system disk
    2. Create new image from that snapshot
    3. Delete old snapshots
    4. Delete old images
    
    Returns:
        dict with new snapshot_id and image_id, or None if failed
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"\n{'#'*60}")
    print(f"# BACKUP ROTATION")
    print(f"{'#'*60}")
    print(f"Timestamp: {timestamp}")
    
    # Get current instance
    instance = get_instance()
    if not instance:
        print("[ERROR] No instance found")
        return None
    
    print(f"\nInstance: {instance.instance_id} ({instance.instance_name})")
    
    # Get system disk
    disk = get_system_disk(instance.instance_id)
    if not disk:
        print("[ERROR] No system disk found")
        return None
    
    print(f"System Disk: {disk.disk_id} ({disk.size} GB)")
    
    # Get old snapshots and images to delete later
    old_snapshots = list_snapshots(verbose=False)
    old_images = list_images("self", verbose=False)
    
    print(f"\nOld snapshots to delete: {len(old_snapshots)}")
    print(f"Old images to delete: {len(old_images)}")
    
    # Backup names
    snap_name = f"backup_{timestamp}"
    img_name = f"backup_{timestamp}"
    description = f"Backup from {instance.instance_id} at {timestamp}"
    
    # Step 1: Create new snapshot
    print(f"\n[1/4] Creating snapshot...")
    new_snapshot_id = create_snapshot(disk.disk_id, snap_name, description)
    if not new_snapshot_id:
        return None
    
    # Step 2: Wait for snapshot
    print(f"\n[2/4] Waiting for snapshot to complete...")
    if not wait_for_snapshot(new_snapshot_id):
        return None
    print(f"  Snapshot ready!")
    
    # Step 3: Create new image from snapshot
    print(f"\n[3/4] Creating image from snapshot...")
    new_image_id = create_image_from_snapshot(new_snapshot_id, img_name, description)
    if not new_image_id:
        return None
    
    # Step 4: Wait for image
    print(f"\n[4/4] Waiting for image to be available...")
    if not wait_for_image(new_image_id):
        return None
    print(f"  Image ready!")
    
    # Step 5: Delete old snapshots
    print(f"\n[5/6] Deleting old snapshots...")
    for snap in old_snapshots:
        if snap.snapshot_id != new_snapshot_id:
            try:
                delete_snapshot(snap.snapshot_id, force=True, verbose=False)
                print(f"  Deleted: {snap.snapshot_id}")
            except Exception as e:
                print(f"  [WARN] Failed: {snap.snapshot_id}: {e}")
    
    # Step 6: Delete old images
    print(f"\n[6/6] Deleting old images...")
    for img in old_images:
        if img.image_id != new_image_id:
            try:
                delete_image(img.image_id, force=True, verbose=False)
                print(f"  Deleted: {img.image_id}")
            except Exception as e:
                print(f"  [WARN] Failed: {img.image_id}: {e}")
    
    print(f"\n{'='*60}")
    print("BACKUP ROTATION COMPLETE")
    print(f"{'='*60}")
    print(f"New Snapshot: {new_snapshot_id}")
    print(f"New Image:    {new_image_id}")
    
    return {"snapshot_id": new_snapshot_id, "image_id": new_image_id}


# %% Create New Backup Function
def create_backup():
    """
    Create a new backup (snapshot + image) without deleting old ones.
    
    Returns:
        dict with new snapshot_id and image_id, or None if failed
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"\n{'#'*60}")
    print(f"# CREATE BACKUP")
    print(f"{'#'*60}")
    print(f"Timestamp: {timestamp}")
    
    # Get current instance
    instance = get_instance()
    if not instance:
        print("[ERROR] No instance found")
        return None
    
    print(f"\nInstance: {instance.instance_id} ({instance.instance_name})")
    
    # Get system disk
    disk = get_system_disk(instance.instance_id)
    if not disk:
        print("[ERROR] No system disk found")
        return None
    
    print(f"System Disk: {disk.disk_id} ({disk.size} GB)")
    
    # Backup names
    snap_name = f"backup_{timestamp}"
    img_name = f"backup_{timestamp}"
    description = f"Backup from {instance.instance_id} at {timestamp}"
    
    # Step 1: Create snapshot
    print(f"\n[1/4] Creating snapshot...")
    new_snapshot_id = create_snapshot(disk.disk_id, snap_name, description)
    if not new_snapshot_id:
        return None
    
    # Step 2: Wait for snapshot
    print(f"\n[2/4] Waiting for snapshot to complete...")
    if not wait_for_snapshot(new_snapshot_id):
        return None
    print(f"  Snapshot ready!")
    
    # Step 3: Create image from snapshot
    print(f"\n[3/4] Creating image from snapshot...")
    new_image_id = create_image_from_snapshot(new_snapshot_id, img_name, description)
    if not new_image_id:
        return None
    
    # Step 4: Wait for image
    print(f"\n[4/4] Waiting for image to be available...")
    if not wait_for_image(new_image_id):
        return None
    print(f"  Image ready!")
    
    print(f"\n{'='*60}")
    print("BACKUP COMPLETE")
    print(f"{'='*60}")
    print(f"Snapshot: {new_snapshot_id}")
    print(f"Image:    {new_image_id}")
    
    return {"snapshot_id": new_snapshot_id, "image_id": new_image_id}


print(f"\n[OK] Functions defined:")
print(f"  create_backup()   - create new backup (keeps old ones)")
print(f"  rotate_backup()   - create new backup and delete old ones")


# %% EXECUTE - Create New Backup
create_backup()


# %% EXECUTE - Perform Backup Rotation
# rotate_backup()


# %% Verify Final State
show_current_state()
