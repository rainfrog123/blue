#!/usr/bin/env python3
"""Test OctoBrowser profile creation with custom titles using boilerplate approach."""

import sys
import time
sys.path.insert(0, '..')

import requests
from config import get_octo_port

API = f"http://localhost:{get_octo_port()}"


def create_profile_with_title(title: str, os_type: str = "mac") -> dict:
    """
    Create profile using boilerplate approach:
    1. Get boilerplate fingerprint via /api/v2/profiles/boilerplate/quick
    2. Fix null dns field
    3. Use /api/v2/profiles with custom title in 'name' field
    
    Returns profile dict on success, None on failure.
    """
    print(f"\n{'='*60}")
    print(f"Creating profile: '{title}' (os={os_type})")
    print('='*60)
    
    # Map os_type to os_arch (permitted: 'x86', 'arm')
    os_arch_map = {"mac": "arm", "win": "x86", "linux": "x86"}
    os_arch = os_arch_map.get(os_type, "x86")
    
    # Step 1: Get boilerplate fingerprint
    print("\n[1] Getting boilerplate fingerprint...")
    resp = requests.post(
        f"{API}/api/v2/profiles/boilerplate/quick",
        json={"os": os_type, "os_arch": os_arch, "count": 1}
    )
    data = resp.json()
    
    if not data.get("success"):
        print(f"  FAILED: {data}")
        return None
    
    bp = data["data"]["boilerplates"][0]
    fp = bp["fp"]
    print(f"  Got fingerprint: {fp.get('os')}/{fp.get('os_arch')}")
    
    # Step 2: Fix null dns field
    print("\n[2] Fixing null fields...")
    if fp.get("dns") is None:
        fp["dns"] = ""
        print("  Fixed: fp.dns = '' (was None)")
    
    # Step 3: Create profile with custom title
    print(f"\n[3] Creating profile...")
    
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
    
    resp = requests.post(f"{API}/api/v2/profiles", json=payload)
    result = resp.json()
    
    if result.get("success"):
        profile = result["data"]
        print(f"\n  SUCCESS!")
        print(f"  UUID:  {profile['uuid']}")
        print(f"  Title: {profile['title']}")
        return profile
    else:
        print(f"\n  FAILED: {result}")
        return None


def cleanup_profile(uuid: str):
    """Delete a profile by UUID"""
    print(f"Deleting profile {uuid[:8]}...")
    resp = requests.post(f"{API}/api/v2/profiles/delete", json={"uuids": [uuid]})
    if resp.json().get("success"):
        print("  Deleted")
    else:
        print(f"  Delete failed: {resp.json()}")


def main():
    print(f"OctoBrowser API: {API}")
    
    # Check if API is available
    try:
        resp = requests.get(f"{API}/api/v2/client/themes", timeout=3)
        if not resp.json().get("success"):
            print("ERROR: OctoBrowser API not responding correctly")
            return 1
    except Exception as e:
        print(f"ERROR: Cannot connect to OctoBrowser API: {e}")
        return 1
    
    print("API is available\n")
    
    # Test: Create profile with custom title
    custom_title = f"Test-Custom-{int(time.time())}"
    profile = create_profile_with_title(custom_title)
    
    if not profile:
        print("\nTEST FAILED: Could not create profile")
        return 1
    
    # Verify title matches
    if profile["title"] == custom_title:
        print(f"\n✓ Title matches expected value")
    else:
        print(f"\n✗ Title mismatch!")
        print(f"  Expected: {custom_title}")
        print(f"  Got: {profile['title']}")
        cleanup_profile(profile["uuid"])
        return 1
    
    # Clean up
    print("\nCleaning up...")
    cleanup_profile(profile["uuid"])
    
    print("\n" + "="*60)
    print("ALL TESTS PASSED")
    print("="*60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
