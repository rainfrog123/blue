#!/usr/bin/env python3
"""
OctoBrowser Profile Manager CLI

Manage OctoBrowser profiles from the command line.

Usage:
    python cli.py list                     # List all profiles
    python cli.py create "My Profile"      # Create profile (default: android)
    python cli.py create "Test" --os win   # Create Windows profile
    python cli.py start UUID               # Start profile
    python cli.py stop UUID                # Stop profile
    python cli.py delete UUID              # Delete profile
    python cli.py info UUID                # Show profile details
    python cli.py test UUID                # Test profile on PixelScan
"""

import argparse
import sys
import time
import json
import requests

from config import OCTO_API, get_octo_port
from octo_helpers import is_octo_running, start_octo_browser, list_profiles

API = None  # Set after checking Octo is running


def get_api():
    """Get API URL, ensuring OctoBrowser is running"""
    global API
    if API is None:
        API = f"http://localhost:{get_octo_port()}"
    return API


def cmd_list(args):
    """List all profiles"""
    try:
        resp = requests.post(f"{get_api()}/api/v2/profiles/list", json={}, timeout=5)
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running. Start it first.")
        return 1
    
    if not data.get("success"):
        print(f"Error: {data}")
        return 1
    
    profiles = data["data"]["profiles"]
    
    if not profiles:
        print("No profiles found.")
        return 0
    
    # Status codes: 0=stopped, 6=running
    status_map = {0: "stopped", 6: "running", 3: "crashed"}
    
    print(f"\n{'Title':<30} {'OS':<10} {'Status':<10} {'UUID'}")
    print("-" * 90)
    
    for p in profiles:
        title = p.get("title", "Untitled")[:28]
        os_type = p.get("os", "?")
        status = status_map.get(p.get("status", 0), f"({p.get('status')})")
        uuid = p.get("uuid", "")
        print(f"{title:<30} {os_type:<10} {status:<10} {uuid}")
    
    print(f"\nTotal: {len(profiles)} profiles")
    return 0


def cmd_create(args):
    """Create a new profile"""
    title = args.title
    os_type = args.os
    
    # Map os_type to os_arch
    os_arch = "arm" if os_type in ["mac", "android"] else "x86"
    
    print(f"Creating {os_type.upper()} profile: {title}")
    
    # Get boilerplate fingerprint
    try:
        resp = requests.post(
            f"{get_api()}/api/v2/profiles/boilerplate/quick",
            json={"os": os_type, "os_arch": os_arch, "count": 1},
            timeout=10
        )
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    if not data.get("success"):
        print(f"Error getting boilerplate: {data}")
        return 1
    
    bp = data["data"]["boilerplates"][0]
    fp = bp["fp"]
    
    # Print fingerprint details
    print(f"\nFingerprint:")
    print(f"  OS: {fp.get('os')} v{fp.get('os_version')}")
    if os_type == "android":
        print(f"  Device: {fp.get('device_model')} ({fp.get('device_type')})")
    else:
        print(f"  Screen: {fp.get('screen')}")
    print(f"  GPU: {fp.get('renderer')}")
    
    # Fix null dns
    if fp.get("dns") is None:
        fp["dns"] = ""
    
    # Enable noise if requested
    if args.noise:
        fp["noise"] = {
            "webgl": True,
            "canvas": True,
            "audio": True,
            "client_rects": True
        }
        print(f"  Noise: enabled")
    
    # Disable WebRTC leaks
    fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}
    
    # Build payload
    storage_opts = bp.get("storage_options", {})
    if os_type == "android":
        storage_opts["extensions"] = False
    
    payload = {
        "title": title,
        "name": title,
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
        "storage_options": storage_opts,
        "extensions": [],
    }
    
    # Create profile
    resp = requests.post(f"{get_api()}/api/v2/profiles", json=payload, timeout=10)
    data = resp.json()
    
    if data.get("success"):
        uuid = data["data"]["uuid"]
        print(f"\n✓ Created: {uuid}")
        return 0
    else:
        print(f"\n✗ Error: {data}")
        return 1


def cmd_start(args):
    """Start a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    
    print(f"Starting profile: {uuid[:16]}...")
    
    # Stop first if running
    requests.post(f"{get_api()}/api/profiles/stop", json={"uuid": uuid}, timeout=5)
    time.sleep(1)
    
    # Start with debug port
    try:
        resp = requests.post(
            f"{get_api()}/api/profiles/start",
            json={"uuid": uuid, "debug_port": True},
            timeout=30
        )
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    if data.get("state") == "STARTED":
        ws = data.get("ws_endpoint", "")
        port = data.get("debug_port", "")
        pid = data.get("browser_pid", "")
        
        print(f"\n✓ Profile started!")
        print(f"  State: {data.get('state')}")
        print(f"  PID: {pid}")
        print(f"  Debug Port: {port}")
        print(f"  WebSocket: {ws}")
        print(f"\nDevTools: http://localhost:{port}")
        return 0
    else:
        print(f"\n✗ Failed to start: {data}")
        return 1


def cmd_stop(args):
    """Stop a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    
    print(f"Stopping profile: {uuid[:16]}...")
    
    try:
        resp = requests.post(
            f"{get_api()}/api/profiles/stop",
            json={"uuid": uuid},
            timeout=10
        )
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    print(f"✓ Stop request sent")
    return 0


def cmd_delete(args):
    """Delete a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    
    if not args.force:
        confirm = input(f"Delete profile {uuid[:16]}...? [y/N] ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return 0
    
    print(f"Deleting profile: {uuid[:16]}...")
    
    # Stop first
    requests.post(f"{get_api()}/api/profiles/stop", json={"uuid": uuid}, timeout=5)
    time.sleep(1)
    
    try:
        resp = requests.post(
            f"{get_api()}/api/v2/profiles/delete",
            json={"uuids": [uuid]},
            timeout=10
        )
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    if data.get("success"):
        print(f"✓ Deleted")
        return 0
    else:
        print(f"✗ Error: {data}")
        return 1


def cmd_purge(args):
    """Delete ALL profiles"""
    try:
        resp = requests.post(f"{get_api()}/api/v2/profiles/list", json={}, timeout=5)
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    if not data.get("success"):
        print(f"Error: {data}")
        return 1
    
    profiles = data["data"]["profiles"]
    
    if not profiles:
        print("No profiles to delete.")
        return 0
    
    print(f"Found {len(profiles)} profiles:")
    for p in profiles:
        print(f"  - {p['title']} ({p['uuid'][:8]}...)")
    
    if not args.force:
        confirm = input(f"\nDelete ALL {len(profiles)} profiles? [y/N] ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return 0
    
    print(f"\nDeleting {len(profiles)} profiles...")
    
    # Stop all first
    for p in profiles:
        requests.post(f"{get_api()}/api/profiles/stop", json={"uuid": p["uuid"]}, timeout=5)
    time.sleep(2)
    
    # Delete all
    uuids = [p["uuid"] for p in profiles]
    resp = requests.post(
        f"{get_api()}/api/v2/profiles/delete",
        json={"uuids": uuids},
        timeout=30
    )
    data = resp.json()
    
    if data.get("success"):
        print(f"✓ Deleted {len(uuids)} profiles")
        return 0
    else:
        print(f"✗ Error: {data}")
        return 1


def cmd_info(args):
    """Show profile details"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    
    try:
        resp = requests.get(f"{get_api()}/api/v2/profiles/{uuid}/view", timeout=5)
        data = resp.json()
    except requests.exceptions.ConnectionError:
        print("Error: OctoBrowser not running.")
        return 1
    
    if not data.get("success"):
        print(f"Error: {data}")
        return 1
    
    profile = data["data"]
    fp = profile.get("fingerprint", {})
    
    print(f"\n{'='*60}")
    print(f"Profile: {profile.get('title', 'Untitled')}")
    print(f"{'='*60}")
    print(f"UUID: {profile.get('uuid')}")
    print(f"OS: {profile.get('os')} v{profile.get('os_version')}")
    print(f"Status: {profile.get('status')} (6=running)")
    print(f"Created: {profile.get('created_at')}")
    print(f"Last Active: {profile.get('last_active')}")
    print(f"Starts: {profile.get('starts_count')}")
    print(f"Run Time: {profile.get('run_time')}s")
    print(f"Size: {profile.get('size_bytes', 0) / 1024 / 1024:.1f} MB")
    print(f"Cookies: {profile.get('cookies_count')}")
    
    if fp:
        print(f"\nFingerprint:")
        for key in ['screen', 'renderer', 'device_model', 'user_agent']:
            if fp.get(key):
                val = fp[key]
                if len(str(val)) > 50:
                    val = str(val)[:50] + "..."
                print(f"  {key}: {val}")
    
    return 0


def cmd_test(args):
    """Test profile fingerprint on PixelScan"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    
    print(f"Testing profile on PixelScan: {uuid[:16]}...")
    print("(This will start the profile and navigate to PixelScan)")
    
    # Start profile
    requests.post(f"{get_api()}/api/profiles/stop", json={"uuid": uuid}, timeout=5)
    time.sleep(2)
    
    resp = requests.post(
        f"{get_api()}/api/profiles/start",
        json={"uuid": uuid, "debug_port": True},
        timeout=30
    )
    data = resp.json()
    
    if data.get("state") != "STARTED":
        print(f"Failed to start profile: {data}")
        return 1
    
    ws = data.get("ws_endpoint")
    print(f"Started. WebSocket: {ws}")
    
    # Use playwright to test
    try:
        import asyncio
        from playwright.async_api import async_playwright
        
        async def run_test():
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(ws)
                context = browser.contexts[0] if browser.contexts else await browser.new_context()
                pages = context.pages
                page = pages[0] if pages else await context.new_page()
                
                # Warm up
                print("Warming up...")
                await page.goto("https://www.google.com", timeout=30000)
                await asyncio.sleep(2)
                
                # Navigate to PixelScan
                print("Navigating to PixelScan...")
                await page.goto("https://pixelscan.net/fingerprint-check", timeout=60000)
                
                print("Waiting for analysis...")
                await asyncio.sleep(12)
                
                # Extract results
                text = await page.evaluate("() => document.body.innerText")
                
                print("\n" + "="*60)
                print("PIXELSCAN RESULTS")
                print("="*60)
                
                # Parse key results
                masking = "Unknown"
                bot = "Unknown"
                proxy = "Unknown"
                
                if "No masking detected" in text:
                    masking = "✓ PASS (No masking detected)"
                elif "Masking detected" in text:
                    masking = "✗ FAIL (Masking detected)"
                
                if "No automated behavior" in text:
                    bot = "✓ PASS"
                
                if "Proxy detected" in text:
                    proxy = "✗ Detected"
                elif "No proxy" in text.lower():
                    proxy = "✓ Not detected"
                
                print(f"Masking: {masking}")
                print(f"Bot: {bot}")
                print(f"Proxy: {proxy}")
                
                # Extract more details
                lines = text.split('\n')
                print("\nDetails:")
                for line in lines:
                    line = line.strip()
                    if any(x in line for x in ['IP Address', 'Country', 'Platform', 'WebGL Renderer', 'Canvas Hash', 'Font hash']):
                        print(f"  {line}")
                
                return 0
        
        result = asyncio.run(run_test())
        
    except ImportError:
        print("\nPlaywright not installed. Install with: pip install playwright")
        print(f"Profile is running. DevTools: http://localhost:{data.get('debug_port')}")
        return 1
    except Exception as e:
        print(f"\nError during test: {e}")
        return 1
    finally:
        # Stop profile
        if not args.keep:
            requests.post(f"{get_api()}/api/profiles/stop", json={"uuid": uuid}, timeout=5)
            print("\nProfile stopped.")
    
    return result


def cmd_status(args):
    """Show OctoBrowser status"""
    port = get_octo_port()
    api = f"http://localhost:{port}"
    
    print(f"OctoBrowser Status")
    print(f"{'='*40}")
    print(f"API: {api}")
    
    try:
        resp = requests.get(f"{api}/api/v2/client/themes", timeout=3)
        if resp.status_code == 200 and resp.json().get("success"):
            print(f"Status: ✓ Running")
            
            # Count profiles
            resp = requests.post(f"{api}/api/v2/profiles/list", json={}, timeout=5)
            profiles = resp.json().get("data", {}).get("profiles", [])
            running = sum(1 for p in profiles if p.get("status") == 6)
            print(f"Profiles: {len(profiles)} total, {running} running")
        else:
            print(f"Status: ✗ API error")
    except requests.exceptions.ConnectionError:
        print(f"Status: ✗ Not running")
    
    return 0


def resolve_uuid(partial):
    """Resolve partial UUID to full UUID"""
    if len(partial) == 32:
        return partial
    
    # Search in profiles
    try:
        resp = requests.post(f"{get_api()}/api/v2/profiles/list", json={}, timeout=5)
        profiles = resp.json().get("data", {}).get("profiles", [])
    except:
        print(f"Error: Cannot list profiles")
        return None
    
    matches = [p for p in profiles if p["uuid"].startswith(partial)]
    
    if len(matches) == 0:
        print(f"Error: No profile found matching '{partial}'")
        return None
    elif len(matches) == 1:
        return matches[0]["uuid"]
    else:
        print(f"Error: Multiple profiles match '{partial}':")
        for p in matches:
            print(f"  {p['uuid']} - {p['title']}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="OctoBrowser Profile Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                      List all profiles
  %(prog)s create "Test Profile"     Create Android profile (default)
  %(prog)s create "Win" --os win     Create Windows profile
  %(prog)s create "Mac" --os mac     Create Mac profile
  %(prog)s start UUID                Start profile (partial UUID ok)
  %(prog)s stop UUID                 Stop profile
  %(prog)s delete UUID               Delete profile
  %(prog)s purge                     Delete ALL profiles
  %(prog)s info UUID                 Show profile details
  %(prog)s test UUID                 Test on PixelScan
  %(prog)s status                    Show OctoBrowser status
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # list
    p_list = subparsers.add_parser("list", aliases=["ls"], help="List all profiles")
    p_list.set_defaults(func=cmd_list)
    
    # create
    p_create = subparsers.add_parser("create", aliases=["new"], help="Create a new profile")
    p_create.add_argument("title", help="Profile title")
    p_create.add_argument("--os", choices=["android", "win", "mac"], default="android",
                          help="OS type (default: android)")
    p_create.add_argument("--noise", action="store_true", default=True,
                          help="Enable fingerprint noise (default: true)")
    p_create.add_argument("--no-noise", action="store_false", dest="noise",
                          help="Disable fingerprint noise")
    p_create.set_defaults(func=cmd_create)
    
    # start
    p_start = subparsers.add_parser("start", help="Start a profile")
    p_start.add_argument("uuid", help="Profile UUID (partial ok)")
    p_start.set_defaults(func=cmd_start)
    
    # stop
    p_stop = subparsers.add_parser("stop", help="Stop a profile")
    p_stop.add_argument("uuid", help="Profile UUID (partial ok)")
    p_stop.set_defaults(func=cmd_stop)
    
    # delete
    p_delete = subparsers.add_parser("delete", aliases=["rm"], help="Delete a profile")
    p_delete.add_argument("uuid", help="Profile UUID (partial ok)")
    p_delete.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    p_delete.set_defaults(func=cmd_delete)
    
    # purge
    p_purge = subparsers.add_parser("purge", help="Delete ALL profiles")
    p_purge.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    p_purge.set_defaults(func=cmd_purge)
    
    # info
    p_info = subparsers.add_parser("info", aliases=["show"], help="Show profile details")
    p_info.add_argument("uuid", help="Profile UUID (partial ok)")
    p_info.set_defaults(func=cmd_info)
    
    # test
    p_test = subparsers.add_parser("test", help="Test profile on PixelScan")
    p_test.add_argument("uuid", help="Profile UUID (partial ok)")
    p_test.add_argument("--keep", action="store_true", help="Keep profile running after test")
    p_test.set_defaults(func=cmd_test)
    
    # status
    p_status = subparsers.add_parser("status", help="Show OctoBrowser status")
    p_status.set_defaults(func=cmd_status)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
