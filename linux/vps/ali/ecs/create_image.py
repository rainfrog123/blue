# %% Create Image - Snapshot Running Instance to Custom Image
"""
Create custom machine images from running ECS instances.

Images capture the full system disk state and can be used to
provision new instances with identical configuration.

Usage:
    Run to create an image from the first available instance.
    Image names are auto-generated with timestamps.
"""
from aliyun_client import print_header
from ecs_operations import list_instances, list_images, create_image

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
