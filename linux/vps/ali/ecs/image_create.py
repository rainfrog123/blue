# %% Setup
"""Create custom images from ECS instances."""
from client import print_header
from ecs_api import list_instances, list_images, create_image

print_header("CREATE IMAGE")


# %% List Instances and Images
print("\nFetching ECS instances...")
instances = list_instances()

print("\nFetching custom images...")
images = list_images("self")


# %% EXECUTE - Create Image from Instance
if instances:
    instance_id = instances[0].instance_id
    create_image(
        instance_id=instance_id,
        image_name=None,  # Auto-generate name
        description="Image created via script"
    )


# %% Check Image Status
list_images("self")

# %%
