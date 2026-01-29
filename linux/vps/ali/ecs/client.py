# %% Alibaba Cloud ECS Client - Shared Module
"""
Shared ECS client configuration.
All scripts import from this module.

Usage:
    from client import ecs_client, ecs_models, REGION_ID, print_header
"""
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
    _script_dir = Path.cwd()

# Add credential loader to path (linux/extra/config)
sys.path.insert(0, str(_script_dir.parent.parent.parent / "extra" / "config"))
from cred_loader import get_alibaba

from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_tea_openapi import models as open_api_models

# Configuration
REGION_ID = "cn-hongkong"

# Load credentials
_alibaba = get_alibaba()
ACCESS_KEY_ID = _alibaba["access_key_id"]
ACCESS_KEY_SECRET = _alibaba["access_key_secret"]

# Create ECS client
_config = open_api_models.Config(
    access_key_id=ACCESS_KEY_ID,
    access_key_secret=ACCESS_KEY_SECRET,
)
_config.endpoint = f"ecs.{REGION_ID}.aliyuncs.com"
ecs_client = EcsClient(_config)


def create_vpc_client():
    """Create VPC client for network operations."""
    from alibabacloud_vpc20160428.client import Client as VpcClient
    config = open_api_models.Config(
        access_key_id=ACCESS_KEY_ID,
        access_key_secret=ACCESS_KEY_SECRET,
    )
    config.endpoint = f"vpc.{REGION_ID}.aliyuncs.com"
    return VpcClient(config)


def print_header(title: str):
    """Print a formatted header."""
    print(f"{'='*60}")
    print(f"ALIBABA CLOUD ECS - {title}")
    print(f"{'='*60}")
    print(f"Region:     {REGION_ID}")
    print(f"Access Key: {ACCESS_KEY_ID[:8]}...")
    print(f"{'='*60}")


# Export everything needed
__all__ = [
    'ecs_client',
    'ecs_models',
    'open_api_models',
    'REGION_ID',
    'ACCESS_KEY_ID',
    'ACCESS_KEY_SECRET',
    'print_header',
    'create_vpc_client',
]
