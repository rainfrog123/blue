# %% Setup
"""Delete custom images."""
from client import ecs_client, ecs_models, REGION_ID, print_header

print_header("DELETE IMAGES")


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
def delete_image(image_id: str, force: bool = False):
    """
    Delete a custom image.
    
    Args:
        image_id: The image ID to delete
        force: Force delete even if image is in use
    
    Returns:
        True if deleted, False otherwise
    """
    print(f"\n{'#'*60}")
    print(f"# DELETE IMAGE")
    print(f"{'#'*60}")
    print(f"Image ID: {image_id}")
    print(f"Force:    {force}")
    
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


def delete_all_images(keep_ids: list = None, force: bool = False):
    """
    Delete all custom images except those in keep_ids.
    
    Args:
        keep_ids: List of image IDs to keep (not delete)
        force: Force delete even if images are in use
    
    Returns:
        Number of images deleted
    """
    keep_ids = keep_ids or []
    
    # Refresh image list
    images = list_custom_images()
    
    # Filter out images to keep
    to_delete = [img for img in images if img.image_id not in keep_ids]
    
    print(f"\n{'#'*60}")
    print(f"# DELETE ALL IMAGES")
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
    
    # Actually delete
    deleted_count = 0
    for img in to_delete:
        print(f"\nDeleting {img.image_id} ({img.image_name})...")
        if delete_image(img.image_id, force=force):
            deleted_count += 1
    
    print(f"\n{'='*60}")
    print(f"DELETION COMPLETE")
    print(f"{'='*60}")
    print(f"Deleted: {deleted_count}/{len(to_delete)} images")
    return deleted_count


print(f"\n[OK] Functions defined:")
print(f"  delete_image(image_id, force=False)")
print(f"  delete_all_images(keep_ids=[], force=False)")


# %% EXECUTE - Delete All Images
# Set keep_ids to preserve specific images
keep_ids = ['m-j6c0nh4f9z0xvos8r3by']  # e.g. ["m-j6c0nh4f9z0xvos8r3by"]

delete_all_images(keep_ids=keep_ids, force=True)
