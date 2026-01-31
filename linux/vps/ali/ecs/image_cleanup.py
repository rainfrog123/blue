# %% Setup
"""Delete custom images."""
from client import print_header
from ecs_api import list_images, delete_image, delete_all_images

print_header("DELETE IMAGES")


# %% List Custom Images
print("\nFetching custom images...")
custom_images = list_images("self")


# %% EXECUTE - Delete All Images (keep specified)
keep_ids = ['m-j6c0nh4f9z0xvos8r3by']  # Image IDs to preserve
delete_all_images(keep_ids=keep_ids, force=True)
