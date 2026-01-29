# %% Setup
"""
ECS Backup Rotation Script
- Creates a new snapshot from the current instance's system disk
- Creates a new image from that snapshot
- Deletes the old snapshot and old image
"""
import time
from datetime import datetime
from client import ecs_client, ecs_models, REGION_ID, print_header

print_header("BACKUP ROTATION")


# %% Helper Functions
def get_instance():
    """Get the first running instance."""
    request = ecs_models.DescribeInstancesRequest(
        region_id=REGION_ID,
        page_size=50
    )
    response = ecs_client.describe_instances(request)
    
    instances = []
    if response.body and response.body.instances and response.body.instances.instance:
        instances = response.body.instances.instance
    
    if not instances:
        print("[ERROR] No instances found")
        return None
    
    return instances[0]


def get_system_disk(instance_id: str):
    """Get the system disk of an instance."""
    request = ecs_models.DescribeDisksRequest(
        region_id=REGION_ID,
        instance_id=instance_id,
        disk_type="system"
    )
    response = ecs_client.describe_disks(request)
    
    disks = []
    if response.body and response.body.disks and response.body.disks.disk:
        disks = response.body.disks.disk
    
    if not disks:
        print(f"[ERROR] No system disk found for instance {instance_id}")
        return None
    
    return disks[0]


def get_snapshots():
    """Get all snapshots."""
    request = ecs_models.DescribeSnapshotsRequest(
        region_id=REGION_ID,
        page_size=50
    )
    response = ecs_client.describe_snapshots(request)
    
    snapshots = []
    if response.body and response.body.snapshots and response.body.snapshots.snapshot:
        snapshots = response.body.snapshots.snapshot
    
    return snapshots


def get_custom_images():
    """Get all custom images."""
    request = ecs_models.DescribeImagesRequest(
        region_id=REGION_ID,
        image_owner_alias="self",
        page_size=50
    )
    response = ecs_client.describe_images(request)
    
    images = []
    if response.body and response.body.images and response.body.images.image:
        images = response.body.images.image
    
    return images


def create_snapshot(disk_id: str, name: str, description: str):
    """Create a snapshot and return its ID."""
    request = ecs_models.CreateSnapshotRequest(
        disk_id=disk_id,
        snapshot_name=name,
        description=description
    )
    response = ecs_client.create_snapshot(request)
    return response.body.snapshot_id


def wait_for_snapshot(snapshot_id: str, timeout: int = 600):
    """Wait for snapshot to complete."""
    print(f"  Waiting for snapshot {snapshot_id}...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        request = ecs_models.DescribeSnapshotsRequest(
            region_id=REGION_ID,
            snapshot_ids=f'["{snapshot_id}"]'
        )
        response = ecs_client.describe_snapshots(request)
        
        if response.body and response.body.snapshots and response.body.snapshots.snapshot:
            snap = response.body.snapshots.snapshot[0]
            status = snap.status
            progress = snap.progress
            print(f"    Status: {status}, Progress: {progress}")
            
            if status == "accomplished":
                return True
            elif status == "failed":
                print(f"  [ERROR] Snapshot failed")
                return False
        
        time.sleep(10)
    
    print(f"  [ERROR] Timeout waiting for snapshot")
    return False


def create_image_from_snapshot(snapshot_id: str, name: str, description: str):
    """Create an image from a snapshot and return its ID."""
    request = ecs_models.CreateImageRequest(
        region_id=REGION_ID,
        snapshot_id=snapshot_id,
        image_name=name,
        description=description
    )
    response = ecs_client.create_image(request)
    return response.body.image_id


def wait_for_image(image_id: str, timeout: int = 600):
    """Wait for image to be available."""
    print(f"  Waiting for image {image_id}...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        request = ecs_models.DescribeImagesRequest(
            region_id=REGION_ID,
            image_id=image_id
        )
        response = ecs_client.describe_images(request)
        
        if response.body and response.body.images and response.body.images.image:
            img = response.body.images.image[0]
            status = img.status
            print(f"    Status: {status}")
            
            if status == "Available":
                return True
            elif status == "CreateFailed":
                print(f"  [ERROR] Image creation failed")
                return False
        
        time.sleep(10)
    
    print(f"  [ERROR] Timeout waiting for image")
    return False


def delete_snapshot(snapshot_id: str):
    """Delete a snapshot."""
    request = ecs_models.DeleteSnapshotRequest(
        snapshot_id=snapshot_id,
        force=True
    )
    ecs_client.delete_snapshot(request)
    print(f"  Deleted snapshot: {snapshot_id}")


def delete_image(image_id: str):
    """Delete an image."""
    request = ecs_models.DeleteImageRequest(
        region_id=REGION_ID,
        image_id=image_id,
        force=True
    )
    ecs_client.delete_image(request)
    print(f"  Deleted image: {image_id}")


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
    snapshots = get_snapshots()
    print(f"\nSnapshots ({len(snapshots)}):")
    for snap in snapshots:
        print(f"  - {snap.snapshot_id}: {snap.snapshot_name or '(unnamed)'}")
        print(f"    Created: {snap.creation_time}")
    
    # Images
    images = get_custom_images()
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
        return None
    
    print(f"\nInstance: {instance.instance_id} ({instance.instance_name})")
    
    # Get system disk
    disk = get_system_disk(instance.instance_id)
    if not disk:
        return None
    
    print(f"System Disk: {disk.disk_id} ({disk.size} GB)")
    
    # Get old snapshots and images to delete later
    old_snapshots = get_snapshots()
    old_images = get_custom_images()
    
    print(f"\nOld snapshots to delete: {len(old_snapshots)}")
    for snap in old_snapshots:
        print(f"  - {snap.snapshot_id}")
    
    print(f"\nOld images to delete: {len(old_images)}")
    for img in old_images:
        print(f"  - {img.image_id}")
    
    # New backup names
    snap_name = f"backup_{timestamp}"
    img_name = f"backup_{timestamp}"
    description = f"Backup from {instance.instance_id} at {timestamp}"
    
    print(f"\nNew snapshot name: {snap_name}")
    print(f"New image name:    {img_name}")
    
    # Step 1: Create new snapshot
    print(f"\n[1/4] Creating snapshot...")
    try:
        new_snapshot_id = create_snapshot(disk.disk_id, snap_name, description)
        print(f"  Created: {new_snapshot_id}")
    except Exception as e:
        print(f"  [ERROR] Failed to create snapshot: {e}")
        return None
    
    # Step 2: Wait for snapshot
    print(f"\n[2/4] Waiting for snapshot to complete...")
    if not wait_for_snapshot(new_snapshot_id):
        print("  [ERROR] Snapshot did not complete")
        return None
    print(f"  Snapshot ready!")
    
    # Step 3: Create new image from snapshot
    print(f"\n[3/4] Creating image from snapshot...")
    try:
        new_image_id = create_image_from_snapshot(new_snapshot_id, img_name, description)
        print(f"  Created: {new_image_id}")
    except Exception as e:
        print(f"  [ERROR] Failed to create image: {e}")
        return None
    
    # Step 4: Wait for image
    print(f"\n[4/4] Waiting for image to be available...")
    if not wait_for_image(new_image_id):
        print("  [ERROR] Image did not become available")
        return None
    print(f"  Image ready!")
    
    # Step 5: Delete old snapshots (except the new one)
    print(f"\n[5/6] Deleting old snapshots...")
    for snap in old_snapshots:
        if snap.snapshot_id != new_snapshot_id:
            try:
                delete_snapshot(snap.snapshot_id)
            except Exception as e:
                print(f"  [WARN] Failed to delete snapshot {snap.snapshot_id}: {e}")
    
    # Step 6: Delete old images (except the new one)
    print(f"\n[6/6] Deleting old images...")
    for img in old_images:
        if img.image_id != new_image_id:
            try:
                delete_image(img.image_id)
            except Exception as e:
                print(f"  [WARN] Failed to delete image {img.image_id}: {e}")
    
    print(f"\n{'='*60}")
    print("BACKUP ROTATION COMPLETE")
    print(f"{'='*60}")
    print(f"New Snapshot: {new_snapshot_id}")
    print(f"New Image:    {new_image_id}")
    
    return {
        "snapshot_id": new_snapshot_id,
        "image_id": new_image_id
    }


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
        return None
    
    print(f"\nInstance: {instance.instance_id} ({instance.instance_name})")
    
    # Get system disk
    disk = get_system_disk(instance.instance_id)
    if not disk:
        return None
    
    print(f"System Disk: {disk.disk_id} ({disk.size} GB)")
    
    # New backup names
    snap_name = f"backup_{timestamp}"
    img_name = f"backup_{timestamp}"
    description = f"Backup from {instance.instance_id} at {timestamp}"
    
    print(f"\nSnapshot name: {snap_name}")
    print(f"Image name:    {img_name}")
    
    # Step 1: Create new snapshot
    print(f"\n[1/4] Creating snapshot...")
    try:
        new_snapshot_id = create_snapshot(disk.disk_id, snap_name, description)
        print(f"  Created: {new_snapshot_id}")
    except Exception as e:
        print(f"  [ERROR] Failed to create snapshot: {e}")
        return None
    
    # Step 2: Wait for snapshot
    print(f"\n[2/4] Waiting for snapshot to complete...")
    if not wait_for_snapshot(new_snapshot_id):
        print("  [ERROR] Snapshot did not complete")
        return None
    print(f"  Snapshot ready!")
    
    # Step 3: Create new image from snapshot
    print(f"\n[3/4] Creating image from snapshot...")
    try:
        new_image_id = create_image_from_snapshot(new_snapshot_id, img_name, description)
        print(f"  Created: {new_image_id}")
    except Exception as e:
        print(f"  [ERROR] Failed to create image: {e}")
        return None
    
    # Step 4: Wait for image
    print(f"\n[4/4] Waiting for image to be available...")
    if not wait_for_image(new_image_id):
        print("  [ERROR] Image did not become available")
        return None
    print(f"  Image ready!")
    
    print(f"\n{'='*60}")
    print("BACKUP COMPLETE")
    print(f"{'='*60}")
    print(f"Snapshot: {new_snapshot_id}")
    print(f"Image:    {new_image_id}")
    
    return {
        "snapshot_id": new_snapshot_id,
        "image_id": new_image_id
    }


print(f"\n[OK] Functions defined:")
print(f"  create_backup()   - create new backup (keeps old ones)")
print(f"  rotate_backup()   - create new backup and delete old ones")


# %% EXECUTE - Create New Backup
create_backup()


# %% EXECUTE - Perform Backup Rotation
# rotate_backup()


# %% Verify Final State
show_current_state()
