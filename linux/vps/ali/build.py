# %% Setup - Alibaba Cloud ECS Client
import sys
import time
import re
from pathlib import Path

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "extra" / "config"))
from cred_loader import get_alibaba

# SSH config path
SSH_CONFIG_PATH = Path.home() / ".ssh" / "config"

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
print(f"ALIBABA CLOUD ECS - BUILD SCRIPT")
print(f"{'='*60}")
print(f"Region:     {REGION_ID}")
print(f"Endpoint:   ecs.{REGION_ID}.aliyuncs.com")
print(f"Access Key: {ACCESS_KEY_ID[:8]}...")
print(f"{'='*60}")


# %% Get VPCs
def create_vpc_client():
    """Create VPC client"""
    from alibabacloud_vpc20160428.client import Client as VpcClient
    config = open_api_models.Config(
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET,
    )
    config.endpoint = f"vpc.{REGION_ID}.aliyuncs.com"
    return VpcClient(config)


try:
    from alibabacloud_vpc20160428 import models as vpc_models
    vpc_client = create_vpc_client()
    
    # Get VPCs
    vpc_request = vpc_models.DescribeVpcsRequest(region_id=REGION_ID, page_size=50)
    vpc_response = vpc_client.describe_vpcs(vpc_request)
    
    # Handle None response
    vpcs = []
    if vpc_response.body and vpc_response.body.vpcs and vpc_response.body.vpcs.vpc:
        vpcs = vpc_response.body.vpcs.vpc
    
    print(f"\nVPCs ({len(vpcs)}):")
    print(f"-" * 60)
    for v in vpcs:
        print(f"  {v.vpc_id}: {v.vpc_name or '(unnamed)'}")
        print(f"    CIDR: {v.cidr_block}, Status: {v.status}")
    
    if vpcs:
        vpc_id = vpcs[0].vpc_id
        print(f"\n[OK] Using VPC: {vpc_id}")
    else:
        vpc_id = None
        print(f"\n[WARN]  No VPCs found in {REGION_ID}")
        
except ImportError:
    print("\n[WARN]  VPC SDK not installed: pip install alibabacloud_vpc20160428")
    vpc_id = None
    vpcs = []
except Exception as e:
    print(f"\n[WARN]  Error getting VPCs: {e}")
    vpc_id = None
    vpcs = []


# %% Get VSwitches
if vpc_id:
    try:
        vswitch_request = vpc_models.DescribeVSwitchesRequest(
            region_id=REGION_ID,
            vpc_id=vpc_id,
            page_size=50
        )
        vswitch_response = vpc_client.describe_vswitches(vswitch_request)
        
        # Handle None response
        vswitches = []
        if vswitch_response.body and vswitch_response.body.v_switches and vswitch_response.body.v_switches.v_switch:
            vswitches = vswitch_response.body.v_switches.v_switch
        
        print(f"\nVSwitches in {vpc_id} ({len(vswitches)}):")
        print(f"-" * 60)
        for vs in vswitches:
            print(f"  {vs.v_switch_id}: {vs.v_switch_name or '(unnamed)'}")
            print(f"    Zone: {vs.zone_id}, CIDR: {vs.cidr_block}")
        
        if vswitches:
            # Prefer cn-hongkong-c zone if available
            vswitch = next((vs for vs in vswitches if vs.zone_id == "cn-hongkong-c"), vswitches[0])
            vswitch_id = vswitch.v_switch_id
            zone_id = vswitch.zone_id
            print(f"\n[OK] Using VSwitch: {vswitch_id} (Zone: {zone_id})")
        else:
            vswitch_id = None
            zone_id = "cn-hongkong-c"
            print(f"\n[WARN]  No VSwitches found in VPC")
    except Exception as e:
        print(f"\n[WARN]  Error getting VSwitches: {e}")
        vswitches = []
        vswitch_id = None
        zone_id = "cn-hongkong-c"
else:
    vswitches = []
    vswitch_id = None
    zone_id = "cn-hongkong-c"
    print("\nSkipping VSwitch lookup (no VPC)")


# %% Get Security Groups
try:
    sg_request = ecs_models.DescribeSecurityGroupsRequest(
        region_id=REGION_ID,
        vpc_id=vpc_id,
        page_size=50
    )
    sg_response = ecs_client.describe_security_groups(sg_request)
    
    # Handle None response
    security_groups = []
    if sg_response.body and sg_response.body.security_groups and sg_response.body.security_groups.security_group:
        security_groups = sg_response.body.security_groups.security_group
    
    print(f"\nSecurity Groups ({len(security_groups)}):")
    print(f"-" * 60)
    for sg in security_groups:
        print(f"  {sg.security_group_id}: {sg.security_group_name or '(unnamed)'}")
        print(f"    VPC: {sg.vpc_id or 'Classic'}")
    
    if security_groups:
        security_group_id = security_groups[0].security_group_id
        print(f"\n[OK] Using Security Group: {security_group_id}")
    else:
        security_group_id = None
        print(f"\n[WARN]  No Security Groups found")
except Exception as e:
    print(f"\n[WARN]  Error getting Security Groups: {e}")
    security_groups = []
    security_group_id = None


# %% Get Key Pairs
try:
    kp_request = ecs_models.DescribeKeyPairsRequest(
        region_id=REGION_ID,
        page_size=50
    )
    kp_response = ecs_client.describe_key_pairs(kp_request)
    
    # Handle None response
    key_pairs = []
    if kp_response.body and kp_response.body.key_pairs and kp_response.body.key_pairs.key_pair:
        key_pairs = kp_response.body.key_pairs.key_pair
    
    print(f"\nKey Pairs ({len(key_pairs)}):")
    print(f"-" * 60)
    for kp in key_pairs:
        print(f"  {kp.key_pair_name}")
        print(f"    Fingerprint: {kp.key_pair_finger_print}")
        print(f"    Created:     {kp.creation_time}")
    
    if key_pairs:
        key_pair_name = key_pairs[0].key_pair_name
        print(f"\n[OK] Using Key Pair: {key_pair_name}")
    else:
        key_pair_name = None
        print(f"\n[WARN]  No Key Pairs found")
except Exception as e:
    print(f"\n[WARN]  Error getting Key Pairs: {e}")
    key_pairs = []
    key_pair_name = None


# %% Network Config Summary
print(f"\n{'='*60}")
print(f"NETWORK CONFIGURATION SUMMARY")
print(f"{'='*60}")
print(f"Zone:           {zone_id}")
print(f"VPC:            {vpc_id or 'NOT FOUND'}")
print(f"VSwitch:        {vswitch_id or 'NOT FOUND'}")
print(f"Security Group: {security_group_id or 'NOT FOUND'}")
print(f"Key Pair:       {key_pair_name or 'NOT FOUND'}")

if vpc_id and vswitch_id and security_group_id:
    print(f"\n[OK] Network config ready for build")
else:
    print(f"\n[WARN]  Missing network config - cannot build")
    print("Create VPC, VSwitch, and Security Group in Alibaba Cloud console")


# %% List Custom Images
def list_images(image_type="self"):
    """
    List available images.
    
    Args:
        image_type: "self" (custom), "system", "others" (shared), "marketplace", or "all"
    """
    if image_type == "all":
        img_request = ecs_models.DescribeImagesRequest(region_id=REGION_ID, page_size=50)
    else:
        img_request = ecs_models.DescribeImagesRequest(
            region_id=REGION_ID, 
            image_owner_alias=image_type,
            page_size=50
        )
    
    img_response = ecs_client.describe_images(img_request)
    images = img_response.body.images.image
    
    type_labels = {"self": "custom", "system": "system", "others": "shared", "marketplace": "marketplace"}
    label = type_labels.get(image_type, image_type)
    
    print(f"\n{'='*70}")
    print(f"AVAILABLE IMAGES ({label}) - Region: {REGION_ID}")
    print(f"{'='*70}")
    
    if not images:
        print("No images found")
        return []
    
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


# Fetch custom images
print("\nFetching custom images...")
custom_images = list_images("self")

if custom_images:
    print(f"\n[OK] Found {len(custom_images)} custom image(s)")
    print(f"  First: {custom_images[0].image_name}")
else:
    print(f"\n[WARN]  No custom images found")


# %% Build Instance Function
def build_instance(
    image_id: str,
    instance_type: str = "ecs.g7a.xlarge",
    instance_name: str = "new-instance",
    system_disk_size: int = 63,
    keypair: str = None,
    host: str = None,
    labels: dict = None,
    spot: bool = False,
    dry_run: bool = True,
):
    """
    Create a new instance from an image.
    
    Args:
        image_id: The image ID to use
        instance_type: Instance type (default: ecs.g7a.xlarge - 4vCPU/16GB)
        instance_name: Name for the new instance
        system_disk_size: System disk size in GB
        keypair: Key pair name for SSH access (default: uses first available)
        host: Hostname for the instance (default: same as instance_name)
        labels: Tags dict for organization/billing, e.g. {"env": "prod", "project": "vps"}
        spot: Use spot instance for cost savings (up to 90% off, but can be reclaimed)
        dry_run: If True, only validate without creating
    
    Returns:
        Tuple (instance_id, public_ip) if created, (None, None) otherwise
    """
    # Use provided keypair or fall back to global
    kp = keypair if keypair is not None else key_pair_name
    # Use provided hostname or fall back to instance name
    hostname = host if host is not None else instance_name
    # Spot strategy
    spot_strategy = "SpotAsPriceGo" if spot else "NoSpot"
    
    print(f"\n{'#'*60}")
    print(f"# {'DRY RUN - ' if dry_run else ''}BUILD INSTANCE FROM IMAGE")
    print(f"{'#'*60}")
    print(f"Image ID:       {image_id}")
    print(f"Instance Type:  {instance_type}")
    print(f"Name:           {instance_name}")
    print(f"Hostname:       {hostname}")
    print(f"System Disk:    {system_disk_size} GB")
    print(f"Key Pair:       {kp or 'NONE'}")
    print(f"Spot Instance:  {'YES (cost savings)' if spot else 'No (on-demand)'}")
    if labels:
        print(f"Labels:         {labels}")
    print(f"Region:         {REGION_ID}")
    print(f"Zone:           {zone_id}")
    print(f"VPC:            {vpc_id}")
    print(f"VSwitch:        {vswitch_id}")
    print(f"Security Group: {security_group_id}")
    
    if not vswitch_id or not security_group_id:
        print(f"\n{'!'*60}")
        print("ERROR: Missing VSwitch or Security Group")
        print("Create network resources in Alibaba Cloud console first")
        print(f"{'!'*60}")
        return None, None
    
    if dry_run:
        print(f"\n{'!'*60}")
        print("DRY RUN - No instance created")
        print("Run: build_instance(image_id, dry_run=False) to create")
        print(f"{'!'*60}")
        return None, None
    
    print(f"\nCreating instance...")
    
    try:
        # Build tags list from labels dict
        tag_list = None
        if labels:
            tag_list = [
                ecs_models.RunInstancesRequestTag(key=k, value=v)
                for k, v in labels.items()
            ]
        
        create_request = ecs_models.RunInstancesRequest(
            region_id=REGION_ID,
            image_id=image_id,
            instance_type=instance_type,
            instance_name=instance_name,
            host_name=hostname,
            security_group_id=security_group_id,
            v_switch_id=vswitch_id,
            zone_id=zone_id,
            key_pair_name=kp,
            spot_strategy=spot_strategy,
            tag=tag_list,
            system_disk=ecs_models.RunInstancesRequestSystemDisk(
                size=str(system_disk_size),
                category="cloud_essd",
            ),
            internet_charge_type="PayByTraffic",
            internet_max_bandwidth_out=100,
            instance_charge_type="PostPaid",
            amount=1,
        )
        
        create_response = ecs_client.run_instances(create_request)
        new_instance_ids = create_response.body.instance_id_sets.instance_id_set
        
        if new_instance_ids:
            new_id = new_instance_ids[0]
            print(f"\n{'='*60}")
            print(f"INSTANCE CREATED SUCCESSFULLY")
            print(f"{'='*60}")
            print(f"New Instance ID: {new_id}")
            print(f"\nWaiting for instance to start...")
            
            # Wait for running status
            for i in range(24):
                time.sleep(5)
                attr_request = ecs_models.DescribeInstanceAttributeRequest(instance_id=new_id)
                attr_response = ecs_client.describe_instance_attribute(attr_request)
                status = attr_response.body.status
                print(f"  [{i+1}/24] Status: {status}")
                if status == "Running":
                    # Get public IP
                    pub_ips = attr_response.body.public_ip_address.ip_address
                    pub_ip = pub_ips[0] if pub_ips else None
                    print(f"\n{'='*60}")
                    print(f"INSTANCE IS RUNNING!")
                    print(f"{'='*60}")
                    print(f"Instance ID: {new_id}")
                    print(f"Public IP:   {pub_ip or 'Allocating...'}")
                    print(f"{'='*60}")
                    return new_id, pub_ip
            
            return new_id, None
        else:
            print("Error: No instance ID returned")
            return None, None
            
    except Exception as e:
        print(f"Error creating instance: {e}")
        return None, None


print(f"\n[OK] build_instance() function defined")
print(f"  Usage: build_instance(image_id, instance_name='my-vps', dry_run=False)")
print(f"  Options:")
print(f"    keypair='key-name'           # SSH key pair")
print(f"    host='my-hostname'           # Hostname (default: instance_name)")
print(f"    labels={{'env': 'prod'}}       # Tags for billing/organization")
print(f"    spot=True                    # Use spot instance (cheaper)")


# %% Update SSH Config
def update_ssh_config(new_ip: str, host_alias: str = "ali_hk"):
    """
    Update SSH config file with new IP for specified host.
    
    Args:
        new_ip: The new IP address
        host_alias: The SSH host alias to update (default: ali_hk)
    """
    if not SSH_CONFIG_PATH.exists():
        print(f"[WARN] SSH config not found: {SSH_CONFIG_PATH}")
        return False
    
    try:
        content = SSH_CONFIG_PATH.read_text(encoding='utf-8')
        
        # Pattern to find Host block and update HostName
        # Matches: Host ali_hk\n    HostName <old_ip>
        pattern = rf'(Host\s+{re.escape(host_alias)}\s*\n\s*HostName\s+)\S+'
        
        if re.search(pattern, content):
            new_content = re.sub(pattern, rf'\g<1>{new_ip}', content)
            SSH_CONFIG_PATH.write_text(new_content, encoding='utf-8')
            print(f"\n[OK] SSH config updated: {host_alias} -> {new_ip}")
            print(f"     You can now: ssh {host_alias}")
            return True
        else:
            print(f"[WARN] Host '{host_alias}' not found in SSH config")
            return False
            
    except Exception as e:
        print(f"[WARN] Failed to update SSH config: {e}")
        return False


# %% Preview Build (Dry Run)
if custom_images and vswitch_id and security_group_id:
    print(f"\n{'='*60}")
    print(f"PREVIEW BUILD - Using first custom image")
    print(f"{'='*60}")
    img = custom_images[0]
    print(f"Image:    {img.image_name}")
    print(f"ID:       {img.image_id}")
    print(f"Key Pair: {key_pair_name or 'NONE'}")
    build_instance(img.image_id, instance_name="preview-vps", dry_run=True)
elif not custom_images:
    print(f"\n{'='*60}")
    print(f"NO CUSTOM IMAGES AVAILABLE")
    print(f"{'='*60}")
    print("Create a custom image first using Alibaba Cloud console")
    print("Or use: list_images('system') to see system images")
else:
    print(f"\n{'='*60}")
    print(f"MISSING NETWORK CONFIG")
    print(f"{'='*60}")
    print("Create VPC, VSwitch, and Security Group first")


# %% EXECUTE BUILD (Create New Instance)
if custom_images and vswitch_id and security_group_id:
    from datetime import datetime
    timestamp = datetime.now().strftime("%m%d-%H%M")  # e.g. 0122-1430
    instance_name = f"vps-{timestamp}"
    
    img = custom_images[0]
    print(f"\n{'#'*60}")
    print(f"# EXECUTING BUILD (SPOT INSTANCE)")
    print(f"{'#'*60}")
    print(f"Image:    {img.image_name} ({img.image_id})")
    print(f"Key Pair: {key_pair_name or 'NONE'}")
    new_instance_id, new_public_ip = build_instance(img.image_id, instance_name=instance_name, spot=True, dry_run=False)
    
    if new_instance_id:
        print(f"\n[OK] Build complete! Instance ID: {new_instance_id}")
        
        # Update SSH config with new IP
        if new_public_ip:
            update_ssh_config(new_public_ip, "ali_hk")
    else:
        print(f"\n[FAIL] Build failed")
else:
    print(f"\n{'#'*60}")
    print(f"# CANNOT BUILD")
    print(f"{'#'*60}")
    if not custom_images:
        print("- No custom images available")
    if not vswitch_id:
        print("- No VSwitch configured")
    if not security_group_id:
        print("- No Security Group configured")
    if not key_pair_name:
        print("- No Key Pair configured (optional but recommended)")
