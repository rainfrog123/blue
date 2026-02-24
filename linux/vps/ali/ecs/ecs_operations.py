# %% Alibaba Cloud ECS Operations - Shared API Functions
"""
Common ECS API operations for instance, image, snapshot, and disk management.

This module provides reusable functions for interacting with Alibaba Cloud ECS.
All functions include verbose output options and proper error handling.

Categories:
    - Instances: list_instances, get_instance
    - Images: list_images, get_latest_image, create_image, delete_image
    - Snapshots: list_snapshots, create_snapshot, delete_snapshot
    - Disks: list_disks, get_system_disk
    - Bulk: delete_all_images, delete_all_snapshots

Usage:
    from ecs_operations import list_instances, create_image, rotate_backup
"""
from __future__ import annotations
from typing import Optional, List, Any
import time
from datetime import datetime
from aliyun_client import ecs_client, ecs_models, REGION_ID


# =============================================================================
# INSTANCES
# =============================================================================

def list_instances(status: Optional[str] = None, verbose: bool = True) -> List[Any]:
    """
    List ECS instances in the region.
    
    Args:
        status: Filter by status (Running, Stopped, etc.) or None for all
        verbose: Print formatted output
    
    Returns:
        List of instance objects
    """
    request = ecs_models.DescribeInstancesRequest(
        region_id=REGION_ID,
        page_size=100
    )
    if status:
        request.status = status
    
    response = ecs_client.describe_instances(request)
    
    instances = []
    if response.body and response.body.instances and response.body.instances.instance:
        instances = response.body.instances.instance
    
    if verbose:
        print(f"\n{'='*70}")
        print(f"ECS INSTANCES - Region: {REGION_ID}" + (f" (status: {status})" if status else ""))
        print(f"{'='*70}")
        
        if not instances:
            print("No instances found")
        else:
            for i, inst in enumerate(instances):
                ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
                public_ip = ips[0] if ips else "N/A"
                
                print(f"\n[{i+1}] {inst.instance_name}")
                print(f"    Instance ID: {inst.instance_id}")
                print(f"    Status:      {inst.status}")
                print(f"    Type:        {inst.instance_type}")
                print(f"    IP:          {public_ip}")
                print(f"    OS:          {inst.osname}")
            
            print(f"\n{'='*70}")
            print(f"Total: {len(instances)} instance(s)")
    
    return instances


def get_instance(instance_id: Optional[str] = None) -> Optional[Any]:
    """
    Get a single instance by ID, or the first available instance.
    
    Args:
        instance_id: Specific instance ID, or None for first instance
    
    Returns:
        Instance object or None
    """
    instances = list_instances(verbose=False)
    
    if not instances:
        return None
    
    if instance_id:
        for inst in instances:
            if inst.instance_id == instance_id:
                return inst
        return None
    
    return instances[0]


# =============================================================================
# IMAGES
# =============================================================================

def list_images(image_type: str = "self", verbose: bool = True) -> List[Any]:
    """
    List available images.
    
    Args:
        image_type: "self" (custom), "system", "others" (shared), "marketplace"
        verbose: Print formatted output
    
    Returns:
        List of image objects
    """
    request = ecs_models.DescribeImagesRequest(
        region_id=REGION_ID,
        page_size=50
    )
    if image_type != "all":
        request.image_owner_alias = image_type
    
    response = ecs_client.describe_images(request)
    
    images = []
    if response.body and response.body.images and response.body.images.image:
        images = response.body.images.image
    
    if verbose:
        type_labels = {"self": "custom", "system": "system", "others": "shared", "marketplace": "marketplace"}
        label = type_labels.get(image_type, image_type)
        
        print(f"\n{'='*70}")
        print(f"IMAGES ({label}) - Region: {REGION_ID}")
        print(f"{'='*70}")
        
        if not images:
            print("No images found")
        else:
            for i, img in enumerate(images):
                print(f"\n[{i+1}] {img.image_name}")
                print(f"    Image ID:    {img.image_id}")
                print(f"    OS:          {img.osname}")
                print(f"    Size:        {img.size} GB")
                print(f"    Status:      {img.status}")
                print(f"    Created:     {img.creation_time}")
            
            print(f"\n{'='*70}")
            print(f"Total: {len(images)} image(s)")
    
    return images


def get_latest_image(image_type: str = "self") -> Optional[Any]:
    """
    Get the most recently created image.
    
    Args:
        image_type: Image type filter
    
    Returns:
        Image object or None
    """
    images = list_images(image_type=image_type, verbose=False)
    
    if not images:
        return None
    
    # Sort by creation_time descending
    sorted_images = sorted(images, key=lambda img: img.creation_time, reverse=True)
    return sorted_images[0]


def create_image(
    instance_id: Optional[str] = None,
    snapshot_id: Optional[str] = None,
    image_name: Optional[str] = None,
    description: Optional[str] = None,
) -> Optional[str]:
    """
    Create a custom image from an instance or snapshot.
    
    Args:
        instance_id: Create from instance (mutually exclusive with snapshot_id)
        snapshot_id: Create from snapshot (mutually exclusive with instance_id)
        image_name: Name for the image (auto-generated if None)
        description: Description for the image
    
    Returns:
        Image ID if created, None otherwise
    """
    if not instance_id and not snapshot_id:
        print("[ERROR] Must specify either instance_id or snapshot_id")
        return None
    
    if instance_id and snapshot_id:
        print("[ERROR] Cannot specify both instance_id and snapshot_id")
        return None
    
    # Auto-generate image name
    if not image_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_name = f"image_{timestamp}"
    
    source = instance_id or snapshot_id
    source_type = "instance" if instance_id else "snapshot"
    
    print(f"\n{'#'*60}")
    print(f"# CREATE IMAGE")
    print(f"{'#'*60}")
    print(f"Source ({source_type}): {source}")
    print(f"Image Name:  {image_name}")
    print(f"Description: {description or '(none)'}")
    
    try:
        request = ecs_models.CreateImageRequest(
            region_id=REGION_ID,
            image_name=image_name,
            description=description or f"Created from {source}"
        )
        if instance_id:
            request.instance_id = instance_id
        else:
            request.snapshot_id = snapshot_id
        
        response = ecs_client.create_image(request)
        image_id = response.body.image_id
        
        print(f"\n{'='*60}")
        print("IMAGE CREATION STARTED")
        print(f"{'='*60}")
        print(f"Image ID:   {image_id}")
        print(f"Image Name: {image_name}")
        return image_id
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("CREATE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return None


def create_image_from_snapshot(
    snapshot_id: str,
    image_name: Optional[str] = None,
    description: Optional[str] = None,
) -> Optional[str]:
    """Convenience wrapper for create_image with snapshot."""
    return create_image(snapshot_id=snapshot_id, image_name=image_name, description=description)


def wait_for_image(image_id: str, timeout: int = 600, verbose: bool = True) -> bool:
    """
    Wait for an image to become available.
    
    Args:
        image_id: The image ID to wait for
        timeout: Maximum wait time in seconds
        verbose: Print progress
    
    Returns:
        True if available, False if failed/timeout
    """
    if verbose:
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
            if verbose:
                print(f"    Status: {status}")
            
            if status == "Available":
                return True
            elif status == "CreateFailed":
                print(f"  [ERROR] Image creation failed")
                return False
        
        time.sleep(10)
    
    print(f"  [ERROR] Timeout waiting for image")
    return False


def delete_image(image_id: str, force: bool = False, verbose: bool = True) -> bool:
    """
    Delete a custom image.
    
    Args:
        image_id: The image ID to delete
        force: Force delete even if in use
        verbose: Print output
    
    Returns:
        True if deleted, False otherwise
    """
    if verbose:
        print(f"\n{'#'*60}")
        print(f"# DELETE IMAGE")
        print(f"{'#'*60}")
        print(f"Image ID: {image_id}")
        print(f"Force:    {force}")
    
    try:
        request = ecs_models.DeleteImageRequest(
            region_id=REGION_ID,
            image_id=image_id,
            force=force
        )
        ecs_client.delete_image(request)
        
        if verbose:
            print(f"\n{'='*60}")
            print("IMAGE DELETED SUCCESSFULLY")
            print(f"{'='*60}")
            print(f"Deleted: {image_id}")
        return True
        
    except Exception as e:
        if verbose:
            print(f"\n{'!'*60}")
            print("DELETE FAILED")
            print(f"{'!'*60}")
            print(f"Error: {e}")
        return False


# =============================================================================
# SNAPSHOTS
# =============================================================================

def list_snapshots(
    disk_id: Optional[str] = None,
    instance_id: Optional[str] = None,
    verbose: bool = True,
) -> List[Any]:
    """
    List snapshots, optionally filtered.
    
    Args:
        disk_id: Filter by disk ID
        instance_id: Filter by instance ID
        verbose: Print formatted output
    
    Returns:
        List of snapshot objects
    """
    request = ecs_models.DescribeSnapshotsRequest(
        region_id=REGION_ID,
        page_size=100
    )
    if disk_id:
        request.disk_id = disk_id
    if instance_id:
        request.instance_id = instance_id
    
    response = ecs_client.describe_snapshots(request)
    
    snapshots = []
    if response.body and response.body.snapshots and response.body.snapshots.snapshot:
        snapshots = response.body.snapshots.snapshot
    
    if verbose:
        print(f"\n{'='*70}")
        print(f"SNAPSHOTS - Region: {REGION_ID}")
        if disk_id:
            print(f"Disk: {disk_id}")
        if instance_id:
            print(f"Instance: {instance_id}")
        print(f"{'='*70}")
        
        if not snapshots:
            print("No snapshots found")
        else:
            for i, snap in enumerate(snapshots):
                print(f"\n[{i+1}] {snap.snapshot_name or '(unnamed)'}")
                print(f"    Snapshot ID: {snap.snapshot_id}")
                print(f"    Disk ID:     {snap.source_disk_id}")
                print(f"    Size:        {snap.source_disk_size} GB")
                print(f"    Status:      {snap.status}")
                print(f"    Progress:    {snap.progress}")
                print(f"    Created:     {snap.creation_time}")
            
            print(f"\n{'='*70}")
            print(f"Total: {len(snapshots)} snapshot(s)")
    
    return snapshots


def create_snapshot(
    disk_id: str,
    snapshot_name: Optional[str] = None,
    description: Optional[str] = None,
    instant_access: bool = False,
) -> Optional[str]:
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
    if not snapshot_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"snap_{timestamp}"
    
    print(f"\n{'#'*60}")
    print(f"# CREATE SNAPSHOT")
    print(f"{'#'*60}")
    print(f"Disk ID:        {disk_id}")
    print(f"Snapshot Name:  {snapshot_name}")
    print(f"Description:    {description or '(none)'}")
    
    try:
        request = ecs_models.CreateSnapshotRequest(
            disk_id=disk_id,
            snapshot_name=snapshot_name,
            description=description or f"Snapshot of {disk_id}",
            instant_access=instant_access
        )
        response = ecs_client.create_snapshot(request)
        snapshot_id = response.body.snapshot_id
        
        print(f"\n{'='*60}")
        print("SNAPSHOT CREATION STARTED")
        print(f"{'='*60}")
        print(f"Snapshot ID:   {snapshot_id}")
        print(f"Snapshot Name: {snapshot_name}")
        return snapshot_id
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("CREATE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return None


def wait_for_snapshot(snapshot_id: str, timeout: int = 600, verbose: bool = True) -> bool:
    """
    Wait for a snapshot to complete.
    
    Args:
        snapshot_id: The snapshot ID to wait for
        timeout: Maximum wait time in seconds
        verbose: Print progress
    
    Returns:
        True if completed, False if failed/timeout
    """
    if verbose:
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
            if verbose:
                print(f"    Status: {status}, Progress: {progress}")
            
            if status == "accomplished":
                return True
            elif status == "failed":
                print(f"  [ERROR] Snapshot failed")
                return False
        
        time.sleep(10)
    
    print(f"  [ERROR] Timeout waiting for snapshot")
    return False


def delete_snapshot(snapshot_id: str, force: bool = False, verbose: bool = True) -> bool:
    """
    Delete a snapshot.
    
    Args:
        snapshot_id: The snapshot ID to delete
        force: Force delete even if in use
        verbose: Print output
    
    Returns:
        True if deleted, False otherwise
    """
    if verbose:
        print(f"\n{'#'*60}")
        print(f"# DELETE SNAPSHOT")
        print(f"{'#'*60}")
        print(f"Snapshot ID: {snapshot_id}")
        print(f"Force:       {force}")
    
    try:
        request = ecs_models.DeleteSnapshotRequest(
            snapshot_id=snapshot_id,
            force=force
        )
        ecs_client.delete_snapshot(request)
        
        if verbose:
            print(f"\n{'='*60}")
            print("SNAPSHOT DELETED SUCCESSFULLY")
            print(f"{'='*60}")
            print(f"Deleted: {snapshot_id}")
        return True
        
    except Exception as e:
        if verbose:
            print(f"\n{'!'*60}")
            print("DELETE FAILED")
            print(f"{'!'*60}")
            print(f"Error: {e}")
        return False


# =============================================================================
# DISKS
# =============================================================================

def list_disks(
    instance_id: Optional[str] = None,
    disk_type: Optional[str] = None,
    verbose: bool = True,
) -> List[Any]:
    """
    List cloud disks, optionally filtered.
    
    Args:
        instance_id: Filter by instance ID
        disk_type: Filter by type ("system" or "data")
        verbose: Print formatted output
    
    Returns:
        List of disk objects
    """
    request = ecs_models.DescribeDisksRequest(
        region_id=REGION_ID,
        page_size=100
    )
    if instance_id:
        request.instance_id = instance_id
    if disk_type:
        request.disk_type = disk_type
    
    response = ecs_client.describe_disks(request)
    
    disks = []
    if response.body and response.body.disks and response.body.disks.disk:
        disks = response.body.disks.disk
    
    if verbose:
        print(f"\n{'='*70}")
        print(f"CLOUD DISKS - Region: {REGION_ID}")
        if instance_id:
            print(f"Instance: {instance_id}")
        if disk_type:
            print(f"Type: {disk_type}")
        print(f"{'='*70}")
        
        if not disks:
            print("No disks found")
        else:
            for i, disk in enumerate(disks):
                print(f"\n[{i+1}] {disk.disk_name or '(unnamed)'}")
                print(f"    Disk ID:     {disk.disk_id}")
                print(f"    Type:        {disk.type} ({disk.category})")
                print(f"    Size:        {disk.size} GB")
                print(f"    Status:      {disk.status}")
                print(f"    Instance:    {disk.instance_id or 'N/A'}")
            
            print(f"\n{'='*70}")
            print(f"Total: {len(disks)} disk(s)")
    
    return disks


def get_system_disk(instance_id: str) -> Optional[Any]:
    """
    Get the system disk of an instance.
    
    Args:
        instance_id: The instance ID
    
    Returns:
        Disk object or None
    """
    disks = list_disks(instance_id=instance_id, disk_type="system", verbose=False)
    return disks[0] if disks else None


# =============================================================================
# BULK OPERATIONS
# =============================================================================

def delete_all_images(keep_ids: Optional[List[str]] = None, force: bool = False) -> int:
    """
    Delete all custom images except those in keep_ids.
    
    Args:
        keep_ids: List of image IDs to keep
        force: Force delete even if in use
    
    Returns:
        Number of images deleted
    """
    keep_ids = keep_ids or []
    images = list_images("self", verbose=False)
    to_delete = [img for img in images if img.image_id not in keep_ids]
    
    print(f"\n{'#'*60}")
    print(f"# DELETE ALL IMAGES")
    print(f"{'#'*60}")
    print(f"Total images:     {len(images)}")
    print(f"Images to keep:   {len(keep_ids)}")
    print(f"Images to delete: {len(to_delete)}")
    
    if not to_delete:
        print("\nNo images to delete")
        return 0
    
    deleted = 0
    for img in to_delete:
        print(f"\nDeleting {img.image_id} ({img.image_name})...")
        if delete_image(img.image_id, force=force, verbose=False):
            print(f"  Deleted: {img.image_id}")
            deleted += 1
    
    print(f"\n{'='*60}")
    print(f"Deleted: {deleted}/{len(to_delete)} images")
    return deleted


def delete_all_snapshots(keep_ids: Optional[List[str]] = None, force: bool = False) -> int:
    """
    Delete all snapshots except those in keep_ids.
    
    Args:
        keep_ids: List of snapshot IDs to keep
        force: Force delete even if in use
    
    Returns:
        Number of snapshots deleted
    """
    keep_ids = keep_ids or []
    snapshots = list_snapshots(verbose=False)
    to_delete = [s for s in snapshots if s.snapshot_id not in keep_ids]
    
    print(f"\n{'#'*60}")
    print(f"# DELETE ALL SNAPSHOTS")
    print(f"{'#'*60}")
    print(f"Total snapshots:     {len(snapshots)}")
    print(f"Snapshots to keep:   {len(keep_ids)}")
    print(f"Snapshots to delete: {len(to_delete)}")
    
    if not to_delete:
        print("\nNo snapshots to delete")
        return 0
    
    deleted = 0
    for snap in to_delete:
        print(f"\nDeleting {snap.snapshot_id} ({snap.snapshot_name or 'unnamed'})...")
        if delete_snapshot(snap.snapshot_id, force=force, verbose=False):
            print(f"  Deleted: {snap.snapshot_id}")
            deleted += 1
    
    print(f"\n{'='*60}")
    print(f"Deleted: {deleted}/{len(to_delete)} snapshots")
    return deleted


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Instances
    'list_instances', 'get_instance',
    # Images
    'list_images', 'get_latest_image',
    'create_image', 'create_image_from_snapshot',
    'wait_for_image', 'delete_image', 'delete_all_images',
    # Snapshots
    'list_snapshots',
    'create_snapshot', 'wait_for_snapshot',
    'delete_snapshot', 'delete_all_snapshots',
    # Disks
    'list_disks', 'get_system_disk',
]
