"""DigitalOcean API helper functions."""

import json
import time
from pathlib import Path

import requests

CRED_PATH = Path("/allah/blue/cred.json")
BASE_URL = "https://api.digitalocean.com/v2"


def load_token() -> str:
    """Load DO token from cred.json."""
    with open(CRED_PATH) as f:
        creds = json.load(f)
    return creds["digitalocean"]["token"]


def get_headers(token: str = None) -> dict:
    """Get API headers with auth."""
    if token is None:
        token = load_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def api_get(endpoint: str, token: str = None) -> dict:
    """Make GET request to DO API."""
    resp = requests.get(f"{BASE_URL}/{endpoint}", headers=get_headers(token))
    resp.raise_for_status()
    return resp.json()


def api_post(endpoint: str, data: dict, token: str = None) -> dict:
    """Make POST request to DO API."""
    resp = requests.post(f"{BASE_URL}/{endpoint}", headers=get_headers(token), json=data)
    resp.raise_for_status()
    return resp.json()


def api_delete(endpoint: str, token: str = None) -> bool:
    """Make DELETE request to DO API."""
    resp = requests.delete(f"{BASE_URL}/{endpoint}", headers=get_headers(token))
    resp.raise_for_status()
    return resp.status_code == 204


# --- Account ---

def get_account() -> dict:
    """Get account info."""
    return api_get("account")["account"]


def get_balance() -> dict:
    """Get account balance."""
    return api_get("customers/my/balance")


# --- SSH Keys ---

def list_ssh_keys() -> list:
    """List all SSH keys."""
    return api_get("account/keys")["ssh_keys"]


def get_ssh_key(key_id: int) -> dict:
    """Get SSH key by ID."""
    return api_get(f"account/keys/{key_id}")["ssh_key"]


def create_ssh_key(name: str, public_key: str) -> dict:
    """Create/register SSH key."""
    data = {"name": name, "public_key": public_key}
    return api_post("account/keys", data)["ssh_key"]


def find_or_create_ssh_key(name: str, public_key: str) -> dict:
    """Find existing SSH key by fingerprint or create new one."""
    import hashlib
    import base64
    
    # Calculate fingerprint from public key
    key_parts = public_key.strip().split()
    if len(key_parts) >= 2:
        key_data = base64.b64decode(key_parts[1])
        fingerprint = hashlib.md5(key_data).hexdigest()
        fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, 32, 2))
        
        # Check if key exists
        for key in list_ssh_keys():
            if key["fingerprint"] == fingerprint:
                return key
    
    return create_ssh_key(name, public_key)


# --- Regions ---

def list_regions(available_only: bool = True) -> list:
    """List all regions."""
    regions = api_get("regions")["regions"]
    if available_only:
        regions = [r for r in regions if r["available"]]
    return regions


# --- Sizes ---

def list_sizes(available_only: bool = True) -> list:
    """List all droplet sizes."""
    sizes = api_get("sizes")["sizes"]
    if available_only:
        sizes = [s for s in sizes if s["available"]]
    return sizes


# --- Images ---

def list_images(image_type: str = "distribution") -> list:
    """List images (distribution, application, or user snapshots)."""
    return api_get(f"images?type={image_type}")["images"]


# --- Droplets ---

def list_droplets() -> list:
    """List all droplets."""
    return api_get("droplets")["droplets"]


def get_droplet(droplet_id: int) -> dict:
    """Get droplet by ID."""
    return api_get(f"droplets/{droplet_id}")["droplet"]


def create_droplet(
    name: str,
    region: str,
    size: str,
    image: str = "ubuntu-24-04-x64",
    ssh_keys: list = None,
    backups: bool = False,
    ipv6: bool = True,
    monitoring: bool = True,
    tags: list = None,
    user_data: str = None,
) -> dict:
    """Create a new droplet."""
    data = {
        "name": name,
        "region": region,
        "size": size,
        "image": image,
        "backups": backups,
        "ipv6": ipv6,
        "monitoring": monitoring,
    }
    if ssh_keys:
        data["ssh_keys"] = ssh_keys
    if tags:
        data["tags"] = tags
    if user_data:
        data["user_data"] = user_data
    
    return api_post("droplets", data)["droplet"]


def delete_droplet(droplet_id: int) -> bool:
    """Delete a droplet."""
    return api_delete(f"droplets/{droplet_id}")


def wait_for_droplet(droplet_id: int, timeout: int = 120) -> dict:
    """Wait for droplet to become active."""
    start = time.time()
    while time.time() - start < timeout:
        droplet = get_droplet(droplet_id)
        if droplet["status"] == "active":
            return droplet
        print(f"  Status: {droplet['status']}...")
        time.sleep(5)
    raise TimeoutError(f"Droplet {droplet_id} did not become active within {timeout}s")


def get_droplet_ip(droplet: dict, ip_type: str = "public") -> str:
    """Extract IP address from droplet."""
    for net in droplet["networks"]["v4"]:
        if net["type"] == ip_type:
            return net["ip_address"]
    return None


# --- Actions ---

def droplet_action(droplet_id: int, action_type: str, **kwargs) -> dict:
    """Perform action on droplet (power_on, power_off, reboot, etc.)."""
    data = {"type": action_type, **kwargs}
    return api_post(f"droplets/{droplet_id}/actions", data)["action"]


def power_on(droplet_id: int) -> dict:
    return droplet_action(droplet_id, "power_on")


def power_off(droplet_id: int) -> dict:
    return droplet_action(droplet_id, "power_off")


def reboot(droplet_id: int) -> dict:
    return droplet_action(droplet_id, "reboot")


def shutdown(droplet_id: int) -> dict:
    return droplet_action(droplet_id, "shutdown")


# --- Snapshots ---

def list_snapshots() -> list:
    """List all snapshots."""
    return api_get("snapshots?resource_type=droplet")["snapshots"]


def get_snapshot(snapshot_id: int) -> dict:
    """Get snapshot by ID."""
    return api_get(f"snapshots/{snapshot_id}")["snapshot"]


def delete_snapshot(snapshot_id: int) -> bool:
    """Delete a snapshot."""
    return api_delete(f"snapshots/{snapshot_id}")


def create_snapshot(droplet_id: int, name: str) -> dict:
    """Create snapshot of droplet (droplet must be off for best results)."""
    return droplet_action(droplet_id, "snapshot", name=name)


def wait_for_action(droplet_id: int, action_id: int, timeout: int = 300) -> dict:
    """Wait for an action to complete."""
    start = time.time()
    while time.time() - start < timeout:
        resp = api_get(f"droplets/{droplet_id}/actions/{action_id}")
        action = resp["action"]
        if action["status"] == "completed":
            return action
        if action["status"] == "errored":
            raise Exception(f"Action {action_id} failed")
        print(f"  Action status: {action['status']}...")
        time.sleep(5)
    raise TimeoutError(f"Action {action_id} did not complete within {timeout}s")


def snapshot_and_delete(droplet_id: int, snapshot_name: str = None) -> dict:
    """Snapshot droplet then delete it. Returns snapshot info."""
    droplet = get_droplet(droplet_id)
    if snapshot_name is None:
        snapshot_name = f"{droplet['name']}-snapshot"
    
    # Power off first for clean snapshot
    if droplet["status"] == "active":
        print("Powering off droplet...")
        shutdown(droplet_id)
        time.sleep(10)
        # Wait for power off
        for _ in range(30):
            d = get_droplet(droplet_id)
            if d["status"] == "off":
                break
            time.sleep(5)
    
    # Create snapshot
    print(f"Creating snapshot '{snapshot_name}'...")
    action = create_snapshot(droplet_id, snapshot_name)
    wait_for_action(droplet_id, action["id"], timeout=600)
    
    # Find the snapshot
    for snap in list_snapshots():
        if snap["name"] == snapshot_name:
            snapshot = snap
            break
    else:
        raise Exception("Snapshot not found after creation")
    
    # Delete droplet
    print("Deleting droplet...")
    delete_droplet(droplet_id)
    
    return snapshot


def restore_from_snapshot(snapshot_id: int, name: str, region: str = None, 
                          size: str = "s-1vcpu-512mb-10gb", ssh_keys: list = None) -> dict:
    """Create new droplet from snapshot."""
    snapshot = get_snapshot(snapshot_id)
    if region is None:
        region = snapshot["regions"][0] if snapshot["regions"] else "sgp1"
    
    return create_droplet(
        name=name,
        region=region,
        size=size,
        image=snapshot_id,
        ssh_keys=ssh_keys,
        ipv6=True,
        monitoring=True,
    )


# --- Reserved IPs (formerly Floating IPs) ---

def list_reserved_ips() -> list:
    """List all reserved IPs."""
    return api_get("reserved_ips")["reserved_ips"]


def get_reserved_ip(ip: str) -> dict:
    """Get reserved IP by address."""
    return api_get(f"reserved_ips/{ip}")["reserved_ip"]


def create_reserved_ip(region: str = None, droplet_id: int = None) -> dict:
    """Create a new reserved IP. Either region or droplet_id must be provided."""
    if droplet_id:
        data = {"droplet_id": droplet_id}
    elif region:
        data = {"region": region}
    else:
        raise ValueError("Either region or droplet_id must be provided")
    return api_post("reserved_ips", data)["reserved_ip"]


def delete_reserved_ip(ip: str) -> bool:
    """Delete a reserved IP."""
    return api_delete(f"reserved_ips/{ip}")


def assign_reserved_ip(ip: str, droplet_id: int) -> dict:
    """Assign reserved IP to a droplet."""
    data = {"type": "assign", "droplet_id": droplet_id}
    return api_post(f"reserved_ips/{ip}/actions", data)["action"]


def unassign_reserved_ip(ip: str) -> dict:
    """Unassign reserved IP from its droplet."""
    data = {"type": "unassign"}
    return api_post(f"reserved_ips/{ip}/actions", data)["action"]
