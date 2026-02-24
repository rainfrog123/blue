# %% Delete Images - Bulk Remove Custom Images
"""
Delete custom machine images with optional preservation list.

Use this to clean up old images while keeping specific ones.
Set keep_ids to preserve important images from deletion.

Usage:
    Modify keep_ids list to specify images to preserve.
    Run delete_all_images() to remove all others.
"""
from aliyun_client import print_header
from ecs_operations import list_images, delete_image, delete_all_images

print_header("DELETE IMAGES")


# %% List Custom Images
print("\nFetching custom images...")
custom_images = list_images("self")


# %% EXECUTE - Delete All Images (keep specified)
keep_ids = ['m-j6c0nh4f9z0xvos8r3by']  # Image IDs to preserve
delete_all_images(keep_ids=keep_ids, force=True)
