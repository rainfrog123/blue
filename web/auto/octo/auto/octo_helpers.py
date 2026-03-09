# %% [markdown]
# # OctoBrowser Helper Functions
# API calls to manage OctoBrowser profiles. Test each function independently.

# %% Imports
import os
import time
import subprocess
import requests

from config import OCTO_APPIMAGE, OCTO_PORT_FILE, OCTO_API, get_octo_port

# %% Module state (tracks current API URL)
_octo_api = OCTO_API

def get_api():
    """Get current OctoBrowser API URL"""
    return _octo_api

# %% Check if Running
def is_octo_running():
    """Check if OctoBrowser API is available"""
    try:
        resp = requests.get(f"{_octo_api}/api/v2/client/themes", timeout=3)
        return resp.status_code == 200 and resp.json().get("success")
    except:
        return False

# %% Start OctoBrowser
def start_octo_browser():
    """Start OctoBrowser if not already running. Returns True on success."""
    global _octo_api
    
    if is_octo_running():
        print(f"OctoBrowser already running at {_octo_api}")
        return True
    
    print("OctoBrowser not running. Starting...")
    
    if not os.path.exists(OCTO_APPIMAGE):
        print(f"ERROR: OctoBrowser not found at {OCTO_APPIMAGE}")
        return False
    
    env = os.environ.copy()
    env["DISPLAY"] = ":1"
    env["OCTO_EXTRA_ARGS"] = "--no-sandbox"
    env["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu-sandbox"
    
    subprocess.Popen(
        [OCTO_APPIMAGE, "--no-sandbox"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    
    print("Waiting for OctoBrowser API...")
    for i in range(60):
        time.sleep(1)
        
        # Re-read port in case it changed
        _octo_api = f"http://localhost:{get_octo_port()}"
        
        if is_octo_running():
            print(f"OctoBrowser started! API: {_octo_api}")
            return True
        
        if i % 10 == 9:
            print(f"  Still waiting... ({i+1}s)")
    
    print("ERROR: OctoBrowser failed to start within 60 seconds")
    return False

# %% List Profiles
def list_profiles():
    """List all OctoBrowser profiles"""
    resp = requests.post(f"{_octo_api}/api/v2/profiles/list", json={})
    data = resp.json()
    if data.get("success"):
        return data["data"]["profiles"]
    raise Exception(f"Failed to list profiles: {data}")

# %% Create Profile
def create_profile(title="Cursor Automation", os_type="mac"):
    """
    Create a new OctoBrowser profile with random fingerprint.
    
    Uses boilerplate approach:
    1. Get fingerprint via /api/v2/profiles/boilerplate/quick
    2. Fix null dns field
    3. Create profile via /api/v2/profiles with custom title
    """
    # Map os_type to os_arch (permitted: 'x86', 'arm')
    os_arch_map = {"mac": "arm", "win": "x86", "linux": "x86"}
    os_arch = os_arch_map.get(os_type, "x86")
    
    # Get boilerplate fingerprint
    resp = requests.post(
        f"{_octo_api}/api/v2/profiles/boilerplate/quick",
        json={"os": os_type, "os_arch": os_arch, "count": 1}
    )
    data = resp.json()
    if not data.get("success"):
        raise Exception(f"Failed to get boilerplate: {data}")
    
    bp = data["data"]["boilerplates"][0]
    fp = bp["fp"]
    
    # Fix null dns field
    if fp.get("dns") is None:
        fp["dns"] = ""
    
    # Create profile with custom title
    payload = {
        "title": title,
        "name": title,  # This becomes the displayed title
        "description": bp.get("description", ""),
        "start_pages": bp.get("start_pages", []),
        "bookmarks": bp.get("bookmarks", []),
        "launch_args": bp.get("launch_args", []),
        "logo": bp.get("logo", ""),
        "tags": bp.get("tags", []),
        "fp": fp,
        "proxy": {"type": "direct"},
        "proxies": bp.get("proxies", []),
        "local_cache": bp.get("local_cache", False),
        "storage_options": bp.get("storage_options", {}),
    }
    
    resp = requests.post(f"{_octo_api}/api/v2/profiles", json=payload)
    data = resp.json()
    
    if data.get("success"):
        print(f"Created profile: {data['data']['title']} ({data['data']['uuid']})")
        return data["data"]["uuid"]
    raise Exception(f"Failed to create profile: {data}")

# %% Start Profile
def start_profile(uuid):
    """Start OctoBrowser profile and return ws_endpoint for Playwright"""
    # Stop if already running
    requests.post(f"{_octo_api}/api/profiles/stop", json={"uuid": uuid})
    time.sleep(2)
    
    # Start with debug_port to get ws_endpoint
    resp = requests.post(
        f"{_octo_api}/api/profiles/start",
        json={"uuid": uuid, "debug_port": True}
    )
    data = resp.json()
    
    ws_endpoint = (
        data.get("ws_endpoint") or 
        data.get("wsEndpoint") or 
        data.get("data", {}).get("ws_endpoint")
    )
    
    if ws_endpoint:
        return ws_endpoint
    
    raise Exception(f"Failed to get ws_endpoint: {data}")

# %% Stop Profile
def stop_profile(uuid):
    """Stop OctoBrowser profile"""
    requests.post(f"{_octo_api}/api/profiles/stop", json={"uuid": uuid})
    print(f"Profile {uuid} stopped")

# %% Get Profile Status
def get_profile_status(uuid):
    """Get profile view/status"""
    resp = requests.get(f"{_octo_api}/api/v2/profiles/{uuid}/view")
    data = resp.json()
    if data.get("success"):
        return data["data"]
    return {}

# %% Delete Profiles (DANGEROUS)
def delete_profiles(uuids):
    """Delete OctoBrowser profiles by UUID list"""
    if not uuids:
        print("No profiles to delete")
        return
    
    # Stop all first
    for uuid in uuids:
        requests.post(f"{_octo_api}/api/profiles/stop", json={"uuid": uuid})
    time.sleep(2)
    
    resp = requests.post(
        f"{_octo_api}/api/v2/profiles/delete",
        json={"uuids": uuids}
    )
    data = resp.json()
    if data.get("success"):
        print(f"Deleted {len(uuids)} profiles")
    else:
        print(f"Delete failed: {data}")

# %% Test: List profiles
if __name__ == "__main__" or "get_ipython" in dir():
    print(f"OctoBrowser API: {_octo_api}")
    print(f"Running: {is_octo_running()}")
    
    if is_octo_running():
        profiles = list_profiles()
        print(f"\nFound {len(profiles)} profiles:")
        for p in profiles:
            status = "running" if p.get("status") == 6 else "stopped"
            print(f"  - {p['title']} ({p['uuid'][:8]}...) [{status}]")
