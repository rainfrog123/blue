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
print(f"ALIBABA CLOUD ECS - CREATE IMAGE")
print(f"{'='*60}")
print(f"Region:     {REGION_ID}")
print(f"Access Key: {ACCESS_KEY_ID[:8]}...")
print(f"{'='*60}")


# %% List ECS Instances
def list_instances():
    """List all ECS instances in the region."""
    request = ecs_models.DescribeInstancesRequest(
        region_id=REGION_ID,
        page_size=50
    )
    response = ecs_client.describe_instances(request)
    
    instances = []
    if response.body and response.body.instances and response.body.instances.instance:
        instances = response.body.instances.instance
    
    print(f"\n{'='*70}")
    print(f"ECS INSTANCES - Region: {REGION_ID}")
    print(f"{'='*70}")
    
    if not instances:
        print("No instances found")
        return []
    
    for i, inst in enumerate(instances):
        ips = inst.public_ip_address.ip_address if inst.public_ip_address else []
        public_ip = ips[0] if ips else "N/A"
        
        print(f"\n[{i+1}] {inst.instance_name}")
        print(f"    Instance ID: {inst.instance_id}")
        print(f"    Status:      {inst.status}")
        print(f"    IP:          {public_ip}")
        print(f"    OS:          {inst.osname}")
    
    print(f"\n{'='*70}")
    print(f"Total: {len(instances)} instance(s)")
    return instances


# Fetch instances
print("\nFetching ECS instances...")
instances = list_instances()


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


# %% Create Image Function
def create_image_from_instance(
    instance_id: str,
    image_name: str = None,
    description: str = None,
    dry_run: bool = True
):
    """
    Create a custom image from an ECS instance.
    
    Args:
        instance_id: The ECS instance ID to create image from
        image_name: Name for the new image (auto-generated if None)
        description: Description for the image
        dry_run: If True, only validate without creating
    
    Returns:
        Image ID if created, None otherwise
    """
    from datetime import datetime
    
    # Auto-generate image name if not provided
    if not image_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_name = f"snapshot_{timestamp}"
    
    print(f"\n{'#'*60}")
    print(f"# {'DRY RUN - ' if dry_run else ''}CREATE IMAGE")
    print(f"{'#'*60}")
    print(f"Instance ID: {instance_id}")
    print(f"Image Name:  {image_name}")
    print(f"Description: {description or '(none)'}")
    
    if dry_run:
        print(f"\n{'='*60}")
        print("DRY RUN - Image NOT created")
        print(f"{'='*60}")
        print("Run with dry_run=False to create")
        return None
    
    try:
        create_request = ecs_models.CreateImageRequest(
            region_id=REGION_ID,
            instance_id=instance_id,
            image_name=image_name,
            description=description or f"Created from {instance_id}"
        )
        response = ecs_client.create_image(create_request)
        
        image_id = response.body.image_id
        
        print(f"\n{'='*60}")
        print("IMAGE CREATION STARTED")
        print(f"{'='*60}")
        print(f"Image ID:   {image_id}")
        print(f"Image Name: {image_name}")
        print(f"\nNote: Image creation takes several minutes.")
        print("Use list_custom_images() to check status.")
        return image_id
        
    except Exception as e:
        print(f"\n{'!'*60}")
        print("CREATE FAILED")
        print(f"{'!'*60}")
        print(f"Error: {e}")
        return None


print(f"\n[OK] Functions defined:")
print(f"  list_instances()")
print(f"  list_custom_images()")
print(f"  create_image_from_instance(instance_id, image_name=None, description=None, dry_run=True)")


# %% DRY RUN - Preview Create Image
# Get first instance (or specify instance_id directly)
if instances:
    instance_id = instances[0].instance_id
    create_image_from_instance(
        instance_id=instance_id,
        image_name=None,  # Auto-generate name
        description="Snapshot created via script",
        dry_run=True
    )


# %% EXECUTE - Create Image from Instance
# Get first instance (or specify instance_id directly)
if instances:
    instance_id = instances[0].instance_id
    create_image_from_instance(
        instance_id=instance_id,
        image_name=None,  # Auto-generate name
        description="Snapshot created via script",
        dry_run=False
    )


# %% Check Image Status
list_custom_images()
