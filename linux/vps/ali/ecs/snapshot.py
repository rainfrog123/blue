# %% Setup
"""Snapshot Manager - Create, list, and delete disk snapshots."""
from client import print_header
from ecs_api import (
    list_disks, list_snapshots,
    create_snapshot, delete_snapshot, delete_all_snapshots
)

print_header("SNAPSHOT MANAGER")


# %% List Snapshots and Disks
print("\nFetching snapshots...")
snapshots = list_snapshots()

print("\nFetching disks...")
disks = list_disks()


# %% EXECUTE - Create Snapshot from Disk
if disks:
    disk_id = disks[0].disk_id
    create_snapshot(
        disk_id=disk_id,
        snapshot_name=None,  # Auto-generate name
        description="Snapshot created via script"
    )


# %% EXECUTE - Delete All Snapshots
keep_ids = []  # Snapshot IDs to preserve
delete_all_snapshots(keep_ids=keep_ids, force=True)


# %% Check Snapshot Status
list_snapshots()
