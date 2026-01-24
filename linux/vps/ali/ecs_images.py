# %% Setup - Alibaba Cloud ECS Client
import sys
from pathlib import Path

# Fix Windows console encoding (skip in Jupyter)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except AttributeError:
    pass  # Jupyter/IPython uses custom streams

# Handle both script and Jupyter environments
try:
    _script_dir = Path(__file__).parent
except NameError:
    _script_dir = Path.cwd()  # Jupyter: assume running from script directory

sys.path.insert(0, str(_script_dir.parent.parent / "extra" / "config"))
from cred_loader import get_alibaba

from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models

# Load credentials
_alibaba = get_alibaba()
ACCESS_KEY_ID = _alibaba["access_key_id"]
ACCESS_KEY_SECRET = _alibaba["access_key_secret"]
REGION_ID = "cn-hongkong"

# Create ECS client
config = open_api_models.Config(
    access_key_id=ACCESS_KEY_ID,
    access_key_secret=ACCESS_KEY_SECRET,
)
config.endpoint = f"ecs.{REGION_ID}.aliyuncs.com"
ecs_client = EcsClient(config)

print(f"{'='*60}")
print(f"ALIBABA CLOUD ECS - DELETE IMAGES")
print(f"{'='*60}")
print(f"Region:     {REGION_ID}")
print(f"Access Key: {ACCESS_KEY_ID[:8]}...")
print(f"{'='*60}")


# %% List Custom Images
def list_custom_images():
    """List all custom images in the region."""
    img_request = ecs_models.DescribeImagesRequest(
        region_id=REGION_ID,
        image_owner_alias="self",
        page_size=50
    )
    img_response = ecs_client.describe_images(img_request)
    
    # Handle None response
    images = []
    if img_response.body and img_response.body.images and img_response.body.images.image:
        images = img_response.body.images.image
    
    print(f"\n{'='*70}")
    print(f"CUSTOM IMAGES - Region: {REGION_ID}")
    print(f"{'='*70}")
    
    if not images:
        print("No custom images found")
        return []
    
    for i, img in enumerate(images):
        print(f"\n[{i+1}] {img.image_name}")
        print(f"    Image ID:    {img.image_id}")
        print(f"    OS:          {img.osname}")
        print(f"    Size:        {img.size} GB")
        print(f"    Status:      {img.status}")
        print(f"    Created:     {img.creation_time}")
    
    print(f"\n{'='*70}")
    print(f"Total: {len(images)} custom image(s)")
    return images


# Fetch custom images
print("\nFetching custom images...")
custom_images = list_custom_images()


# %% Delete Image Function
def delete_image(image_id: str, force: bool = False, dry_run: bool = True):
    """
    Delete a custom image.
    
    Args:
        image_id: The image ID to delete
        force: Force delete even if image is in use
        dry_run: If True, only validate without deleting
    
    Returns:
        True if deleted, False otherwise
    """
    print(f"\n{'#'*60}")
    print(f"# {'DRY RUN - ' if dry_run else ''}DELETE IMAGE")
    print(f"{'#'*60}")
    print(f"Image ID: {image_id}")
    print(f"Force:    {force}")
    
    if dry_run:
        print(f"\n{'='*60}")
        print("DRY RUN - Image NOT deleted")
        print(f"{'='*60}")
        print("Run with dry_run=False to delete")
        return False
    
    try:
        delete_request = ecs_models.DeleteImageRequest(
            region_id=REGION_ID,
            image_id=image_id,
            force=force
        )
        ecs_client.delete_image(delete_request)
        
        print(f"\n{'='*60}")
        print("IMAGE DELETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"Deleted: {image_id}")
        return True
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("DELETE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return False


def delete_all_images(keep_ids: list = None, force: bool = False, dry_run: bool = True):
    """
    Delete all custom images except those in keep_ids.
    
    Args:
        keep_ids: List of image IDs to keep (not delete)
        force: Force delete even if images are in use
        dry_run: If True, only show what would be deleted
    
    Returns:
        Number of images deleted
    """
    keep_ids = keep_ids or []
    
    # Refresh image list
    images = list_custom_images()
    
    # Filter out images to keep
    to_delete = [img for img in images if img.image_id not in keep_ids]
    
    print(f"\n{'#'*60}")
    print(f"# {'DRY RUN - ' if dry_run else ''}DELETE ALL IMAGES")
    print(f"{'#'*60}")
    print(f"Total images:     {len(images)}")
    print(f"Images to keep:   {len(keep_ids)}")
    print(f"Images to delete: {len(to_delete)}")
    
    if keep_ids:
        print(f"\nKeeping:")
        for kid in keep_ids:
            print(f"  - {kid}")
    
    if not to_delete:
        print("\nNo images to delete")
        return 0
    
    print(f"\nTo be deleted:")
    for img in to_delete:
        print(f"  - {img.image_id}: {img.image_name}")
    
    if dry_run:
        print(f"\n{'='*60}")
        print("DRY RUN - No images deleted")
        print(f"{'='*60}")
        print("Run with dry_run=False to delete")
        return 0
    
    # Actually delete
    deleted_count = 0
    for img in to_delete:
        print(f"\nDeleting {img.image_id} ({img.image_name})...")
        if delete_image(img.image_id, force=force, dry_run=False):
            deleted_count += 1
    
    print(f"\n{'='*60}")
    print(f"DELETION COMPLETE")
    print(f"{'='*60}")
    print(f"Deleted: {deleted_count}/{len(to_delete)} images")
    return deleted_count


print(f"\n[OK] Functions defined:")
print(f"  delete_image(image_id, force=False, dry_run=True)")
print(f"  delete_all_images(keep_ids=[], force=False, dry_run=True)")


# %% DRY RUN - Preview Delete All Images
# Set keep_ids to preserve specific images
keep_ids = []  # e.g. ["m-j6c0nh4f9z0xvos8r3by"]

delete_all_images(keep_ids=keep_ids, dry_run=True)


# %% EXECUTE - Delete All Images
# Set keep_ids to preserve specific images
keep_ids = ['m-j6c0nh4f9z0xvos8r3by']  # e.g. ["m-j6c0nh4f9z0xvos8r3by"]

delete_all_images(keep_ids=keep_ids, force=True, dry_run=False)

