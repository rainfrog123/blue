# Alibaba Cloud ECS Manager

A Python toolkit for managing Alibaba Cloud ECS (Elastic Compute Service) instances, images, snapshots, and backups in the Hong Kong region.

## Features

- **Instance Lifecycle**: Provision and terminate ECS instances from custom images
- **Backup Management**: Create/rotate snapshots and custom images
- **Spot Instance Support**: Cost-effective spot pricing with automatic fallback
- **SSH/VNC Integration**: Auto-update local SSH config and VNC connections
- **Security Diagnostics**: Debug firewall rules and port accessibility

## Prerequisites

### Python Packages

```bash
pip install alibabacloud_ecs20140526 alibabacloud_vpc20160428 alibabacloud_tea_openapi
```

### Credentials

Requires Alibaba Cloud credentials configured via `cred_loader` module (located in `linux/extra/`):
- `access_key_id`
- `access_key_secret`

## File Structure

```
├── aliyun_client.py        # Shared client configuration and credentials
├── ecs_operations.py       # Common API operations (instances, images, snapshots, disks)
│
├── provision_instance.py   # Create new ECS instances from custom images
├── terminate_instance.py   # Stop and delete ECS instances
│
├── create_image.py         # Create custom images from running instances
├── delete_images.py        # Bulk delete custom images
├── manage_snapshots.py     # Create and delete disk snapshots
├── rotate_backup.py        # Full backup rotation (snapshot + image, cleanup old)
│
├── explore_api.py          # API exploration and testing utilities
└── diagnose_firewall.py    # Security group rule diagnostics
```

## Common Workflows

### Provision a New Instance

```python
# In provision_instance.py
# Uses latest custom image, creates spot instance with auto-naming
build_instance(image_id, instance_name="blue-0224", spot=True)
```

After provisioning, the script automatically:
1. Updates `~/.ssh/config` with the new IP
2. Updates RealVNC saved connections
3. Clears old SSH known_hosts entries

### Create a Backup

```python
# In rotate_backup.py
create_backup()    # Create new snapshot + image (keeps existing)
rotate_backup()    # Create new backup AND delete old ones
```

### Terminate an Instance

```python
# In terminate_instance.py
release_all()      # Stop instance, then delete (auto-deletes system disk)
```

### Debug Port Access

```bash
python diagnose_firewall.py 47.86.7.159 443
```

## Configuration

Default region: `cn-hongkong`

Edit `aliyun_client.py` to change:
- `REGION_ID` - Target region
- Endpoint configuration

## Interactive Usage

All scripts use `# %%` cell markers for interactive execution in VS Code/Jupyter:

1. Open any script in VS Code with Python extension
2. Run cells interactively with `Shift+Enter`
3. Functions are defined but not auto-executed (except where noted)

## API Reference

### ecs_operations.py

**Instances**
- `list_instances(status=None, verbose=True)` - List all instances
- `get_instance(instance_id=None)` - Get specific or first instance

**Images**
- `list_images(image_type="self", verbose=True)` - List images
- `get_latest_image(image_type="self")` - Get most recent image
- `create_image(instance_id, snapshot_id, image_name, description)`
- `delete_image(image_id, force=False)`
- `wait_for_image(image_id, timeout=600)`

**Snapshots**
- `list_snapshots(disk_id=None, instance_id=None, verbose=True)`
- `create_snapshot(disk_id, snapshot_name, description, instant_access=False)`
- `delete_snapshot(snapshot_id, force=False)`
- `wait_for_snapshot(snapshot_id, timeout=600)`

**Disks**
- `list_disks(instance_id=None, disk_type=None, verbose=True)`
- `get_system_disk(instance_id)` - Get instance's system disk

**Bulk Operations**
- `delete_all_images(keep_ids=[], force=False)`
- `delete_all_snapshots(keep_ids=[], force=False)`
