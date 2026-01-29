# %% Setup
"""Snapshot Manager - Create, list, and delete disk snapshots."""
from datetime import datetime
from client import ecs_client, ecs_models, REGION_ID, print_header

print_header("SNAPSHOT MANAGER")


# %% List Disks for Instance
def list_disks(instance_id: str = None):
    """
    List cloud disks, optionally filtered by instance.
    
    Args:
        instance_id: Filter disks by instance (None = all disks)
    
    Returns:
        List of disk objects
    """
    request = ecs_models.DescribeDisksRequest(
        region_id=REGION_ID,
        page_size=50
    )
    if instance_id:
        request.instance_id = instance_id
    
    response = ecs_client.describe_disks(request)
    
    disks = []
    if response.body and response.body.disks and response.body.disks.disk:
        disks = response.body.disks.disk
    
    print(f"\n{'='*70}")
    print(f"CLOUD DISKS - Region: {REGION_ID}")
    if instance_id:
        print(f"Instance: {instance_id}")
    print(f"{'='*70}")
    
    if not disks:
        print("No disks found")
        return []
    
    for i, disk in enumerate(disks):
        print(f"\n[{i+1}] {disk.disk_name or '(unnamed)'}")
        print(f"    Disk ID:     {disk.disk_id}")
        print(f"    Type:        {disk.type} ({disk.category})")
        print(f"    Size:        {disk.size} GB")
        print(f"    Status:      {disk.status}")
        print(f"    Instance:    {disk.instance_id or 'N/A'}")
        print(f"    Device:      {disk.device or 'N/A'}")
    
    print(f"\n{'='*70}")
    print(f"Total: {len(disks)} disk(s)")
    return disks


# %% List Snapshots
def list_snapshots(disk_id: str = None, instance_id: str = None):
    """
    List snapshots, optionally filtered by disk or instance.
    
    Args:
        disk_id: Filter by disk ID
        instance_id: Filter by instance ID
    
    Returns:
        List of snapshot objects
    """
    request = ecs_models.DescribeSnapshotsRequest(
        region_id=REGION_ID,
        page_size=50
    )
    if disk_id:
        request.disk_id = disk_id
    if instance_id:
        request.instance_id = instance_id
    
    response = ecs_client.describe_snapshots(request)
    
    snapshots = []
    if response.body and response.body.snapshots and response.body.snapshots.snapshot:
        snapshots = response.body.snapshots.snapshot
    
    print(f"\n{'='*70}")
    print(f"SNAPSHOTS - Region: {REGION_ID}")
    if disk_id:
        print(f"Disk: {disk_id}")
    if instance_id:
        print(f"Instance: {instance_id}")
    print(f"{'='*70}")
    
    if not snapshots:
        print("No snapshots found")
        return []
    
    for i, snap in enumerate(snapshots):
        print(f"\n[{i+1}] {snap.snapshot_name or '(unnamed)'}")
        print(f"    Snapshot ID: {snap.snapshot_id}")
        print(f"    Disk ID:     {snap.source_disk_id}")
        print(f"    Disk Type:   {snap.source_disk_type}")
        print(f"    Size:        {snap.source_disk_size} GB")
        print(f"    Status:      {snap.status}")
        print(f"    Progress:    {snap.progress}")
        print(f"    Created:     {snap.creation_time}")
        if snap.description:
            print(f"    Description: {snap.description}")
    
    print(f"\n{'='*70}")
    print(f"Total: {len(snapshots)} snapshot(s)")
    return snapshots


# Fetch all snapshots
print("\nFetching snapshots...")
snapshots = list_snapshots()


# %% Create Snapshot
def create_snapshot(
    disk_id: str,
    snapshot_name: str = None,
    description: str = None,
    instant_access: bool = False
):
    """
    Create a snapshot from a cloud disk.
    
    Args:
        disk_id: The disk ID to snapshot
        snapshot_name: Name for the snapshot (auto-generated if None)
        description: Description for the snapshot
        instant_access: Enable instant access (faster but costs more)
    
    Returns:
        Snapshot ID if created, None otherwise
    """
    # Auto-generate snapshot name if not provided
    if not snapshot_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"snap_{timestamp}"
    
    print(f"\n{'#'*60}")
    print(f"# CREATE SNAPSHOT")
    print(f"{'#'*60}")
    print(f"Disk ID:        {disk_id}")
    print(f"Snapshot Name:  {snapshot_name}")
    print(f"Description:    {description or '(none)'}")
    print(f"Instant Access: {instant_access}")
    
    try:
        create_request = ecs_models.CreateSnapshotRequest(
            disk_id=disk_id,
            snapshot_name=snapshot_name,
            description=description or f"Snapshot of {disk_id}",
            instant_access=instant_access
        )
        response = ecs_client.create_snapshot(create_request)
        
        snapshot_id = response.body.snapshot_id
        
        print(f"\n{'='*60}")
        print("SNAPSHOT CREATION STARTED")
        print(f"{'='*60}")
        print(f"Snapshot ID:   {snapshot_id}")
        print(f"Snapshot Name: {snapshot_name}")
        print(f"\nNote: Snapshot creation may take several minutes.")
        print("Use list_snapshots() to check status.")
        return snapshot_id
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("CREATE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return None


# %% Delete Snapshot
def delete_snapshot(snapshot_id: str, force: bool = False):
    """
    Delete a snapshot.
    
    Args:
        snapshot_id: The snapshot ID to delete
        force: Force delete even if snapshot is in use
    
    Returns:
        True if deleted, False otherwise
    """
    print(f"\n{'#'*60}")
    print(f"# DELETE SNAPSHOT")
    print(f"{'#'*60}")
    print(f"Snapshot ID: {snapshot_id}")
    print(f"Force:       {force}")
    
    try:
        delete_request = ecs_models.DeleteSnapshotRequest(
            snapshot_id=snapshot_id,
            force=force
        )
        ecs_client.delete_snapshot(delete_request)
        
        print(f"\n{'='*60}")
        print("SNAPSHOT DELETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"Deleted: {snapshot_id}")
        return True
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("DELETE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return False


# %% Delete All Snapshots
def delete_all_snapshots(keep_ids: list = None, force: bool = False):
    """
    Delete all snapshots except those in keep_ids.
    
    Args:
        keep_ids: List of snapshot IDs to keep (not delete)
        force: Force delete even if snapshots are in use
    
    Returns:
        Number of snapshots deleted
    """
    keep_ids = keep_ids or []
    
    # Refresh snapshot list
    snapshots = list_snapshots()
    
    # Filter out snapshots to keep
    to_delete = [snap for snap in snapshots if snap.snapshot_id not in keep_ids]
    
    print(f"\n{'#'*60}")
    print(f"# DELETE ALL SNAPSHOTS")
    print(f"{'#'*60}")
    print(f"Total snapshots:     {len(snapshots)}")
    print(f"Snapshots to keep:   {len(keep_ids)}")
    print(f"Snapshots to delete: {len(to_delete)}")
    
    if keep_ids:
        print(f"\nKeeping:")
        for kid in keep_ids:
            print(f"  - {kid}")
    
    if not to_delete:
        print("\nNo snapshots to delete")
        return 0
    
    print(f"\nTo be deleted:")
    for snap in to_delete:
        print(f"  - {snap.snapshot_id}: {snap.snapshot_name or '(unnamed)'}")
    
    # Actually delete
    deleted_count = 0
    for snap in to_delete:
        print(f"\nDeleting {snap.snapshot_id} ({snap.snapshot_name or 'unnamed'})...")
        if delete_snapshot(snap.snapshot_id, force=force):
            deleted_count += 1
    
    print(f"\n{'='*60}")
    print(f"DELETION COMPLETE")
    print(f"{'='*60}")
    print(f"Deleted: {deleted_count}/{len(to_delete)} snapshots")
    return deleted_count


print(f"\n[OK] Functions defined:")
print(f"  list_disks(instance_id=None)")
print(f"  list_snapshots(disk_id=None, instance_id=None)")
print(f"  create_snapshot(disk_id, snapshot_name=None, description=None, instant_access=False)")
print(f"  delete_snapshot(snapshot_id, force=False)")
print(f"  delete_all_snapshots(keep_ids=[], force=False)")


# %% List Disks (to find disk IDs for snapshotting)
print("\nFetching disks...")
disks = list_disks()


# %% EXECUTE - Create Snapshot from Disk
# Get first disk (or specify disk_id directly)
if disks:
    disk_id = disks[0].disk_id
    create_snapshot(
        disk_id=disk_id,
        snapshot_name=None,  # Auto-generate name
        description="Snapshot created via script"
    )


# %% EXECUTE - Delete All Snapshots
keep_ids = []  # e.g. ["s-j6c0nh4f9z0xvos8r3by"]
delete_all_snapshots(keep_ids=keep_ids, force=True)


# %% Check Snapshot Status
list_snapshots()
