#!/usr/bin/env python3
"""
OctoBrowser API Client - Profile Management

Usage:
    python api_client.py status            # Check if running
    python api_client.py list              # List profiles
    python api_client.py templates         # List profile templates
    python api_client.py create "Name"     # Create profile
    python api_client.py start UUID        # Start profile
    python api_client.py stop UUID         # Stop profile
"""

import json
import os
import re
import subprocess
import time
import requests
from urllib.parse import urlparse, unquote

from config import get_octo_port, OCTO_APPIMAGE

API = None


def get_api():
    """Get API URL"""
    global API
    if API is None:
        API = f"http://localhost:{get_octo_port()}"
    return API


def api_get(endpoint, timeout=5):
    """GET request to API"""
    try:
        resp = requests.get(f"{get_api()}{endpoint}", timeout=timeout)
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": "OctoBrowser not running"}
    except Exception as e:
        return {"error": str(e)}


def api_post(endpoint, data=None, timeout=10):
    """POST request to API"""
    try:
        resp = requests.post(f"{get_api()}{endpoint}", json=data or {}, timeout=timeout)
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": "OctoBrowser not running"}
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# Helper Functions (for programmatic use)
# =============================================================================

def is_running():
    """Check if OctoBrowser API is available"""
    resp = api_get("/api/v2/client/themes", timeout=3)
    return resp.get("success", False)


def start_octo_browser(timeout=60):
    """
    Start OctoBrowser if not already running.
    
    Returns:
        True if running (or started successfully), False on failure
    """
    global API
    
    if is_running():
        print(f"OctoBrowser already running at {get_api()}")
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
    for i in range(timeout):
        time.sleep(1)
        
        # Re-read port in case it changed
        API = f"http://localhost:{get_octo_port()}"
        
        if is_running():
            print(f"OctoBrowser started! API: {API}")
            return True
        
        if i % 10 == 9:
            print(f"  Still waiting... ({i+1}s)")
    
    print(f"ERROR: OctoBrowser failed to start within {timeout} seconds")
    return False


def list_profiles():
    """List all profiles. Returns list of profile dicts."""
    resp = api_post("/api/v2/profiles/list")
    if resp.get("success"):
        return resp["data"]["profiles"]
    return []


def start_profile(uuid, debug_port=True):
    """
    Start profile and return ws_endpoint for Playwright.
    
    Args:
        uuid: Profile UUID
        debug_port: True for auto-assign, or specific port number (e.g., 9222)
    """
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(1)
    
    resp = api_post("/api/profiles/start", {"uuid": uuid, "debug_port": debug_port}, timeout=30)
    
    ws_endpoint = resp.get("ws_endpoint") or resp.get("wsEndpoint")
    actual_port = resp.get("debug_port")
    
    if ws_endpoint:
        return {"ws_endpoint": ws_endpoint, "debug_port": actual_port, "state": resp.get("state")}
    
    return {"error": str(resp)}


def stop_profile(uuid):
    """Stop a profile."""
    return api_post("/api/profiles/stop", {"uuid": uuid}, timeout=10)


def delete_profile(uuid, force=False):
    """Delete a profile by UUID."""
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(1)
    return api_post("/api/v2/profiles/delete", {"uuids": [uuid]})


def delete_profiles(uuids):
    """Delete multiple profiles by UUID list."""
    if not uuids:
        return {"success": True, "message": "No profiles to delete"}
    
    for uuid in uuids:
        api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(2)
    
    return api_post("/api/v2/profiles/delete", {"uuids": uuids}, timeout=30)


def parse_proxy_url(url):
    """Parse proxy URL into OctoBrowser API format."""
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    proxy_type = "http" if scheme in ("http", "https") else scheme if scheme in ("socks4", "socks5") else "http"
    return {
        "type": "new",
        "data": {
            "type": proxy_type,
            "ip": parsed.hostname or "",
            "port": parsed.port or 8080,
            "login": unquote(parsed.username or ""),
            "password": unquote(parsed.password or "")
        }
    }


def resolve_uuid(partial):
    """Resolve partial UUID to full UUID"""
    if not partial:
        return None
    if len(partial) == 32:
        return partial
    resp = api_post("/api/v2/profiles/list")
    profiles = resp.get("data", {}).get("profiles", [])
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


# =============================================================================
# API Commands
# =============================================================================

def cmd_status(args):
    """Show OctoBrowser status"""
    api = get_api()
    print("OctoBrowser Status")
    print("=" * 50)
    print(f"API: {api}")

    resp = api_get("/api/v2/client/themes", timeout=3)
    if resp.get("error"):
        print("Status: ✗ Not running")
        return 1

    if resp.get("success"):
        print("Status: ✓ Running")
    else:
        print("Status: ✗ API error")
        return 1

    ver = api_get("/api/update")
    if not ver.get("error"):
        print(f"Version: {ver.get('current', '?')}")

    resp = api_post("/api/v2/profiles/list")
    profiles = resp.get("data", {}).get("profiles", [])
    running = sum(1 for p in profiles if p.get("status") == 6)
    print(f"Profiles: {len(profiles)} total, {running} running")
    return 0


def cmd_version(args):
    """Show OctoBrowser version"""
    resp = api_get("/api/update")
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    print(f"Current: {resp.get('current', '?')}")
    print(f"Latest:  {resp.get('latest', '?')}")
    return 0


def cmd_list(args):
    """List all profiles"""
    resp = api_post("/api/v2/profiles/list")
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    if not resp.get("success"):
        print(f"Error: {resp}")
        return 1
    profiles = resp["data"]["profiles"]
    if not profiles:
        print("No profiles found.")
        return 0
    status_map = {0: "stopped", 1: "starting", 6: "running", 3: "crashed"}
    if args.json:
        print(json.dumps(profiles, indent=2))
        return 0
    print(f"\n{'Title':<30} {'OS':<10} {'Status':<10} {'UUID'}")
    print("-" * 90)
    for p in profiles:
        title = (p.get("title") or "Untitled")[:28]
        os_type = p.get("os", "?")
        status = status_map.get(p.get("status", 0), f"({p.get('status')})")
        print(f"{title:<30} {os_type:<10} {status:<10} {p.get('uuid', '')}")
    print(f"\nTotal: {len(profiles)} profiles")
    return 0


def cmd_active(args):
    """List running profiles"""
    resp = api_get("/api/profiles/active")
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    if not resp:
        print("No active profiles.")
        return 0
    if args.json:
        print(json.dumps(resp, indent=2))
        return 0
    print(f"\n{'UUID':<34} {'State':<10} {'Port':<8} {'PID'}")
    print("-" * 80)
    for p in resp:
        print(f"{p.get('uuid', '')[:32]:<34} {p.get('state', '?'):<10} {p.get('debug_port', ''):<8} {p.get('browser_pid', '')}")
    print(f"\nActive: {len(resp)} profiles")
    return 0


def ensure_profile_slot():
    """Delete oldest profile if limit reached. Returns True if slot available."""
    # Check current count vs limit by trying to get profile list
    resp = api_post("/api/v2/profiles/list")
    if not resp.get("success"):
        return True  # Can't check, assume OK
    
    profiles = resp.get("data", {}).get("profiles", [])
    # OctoBrowser free limit is typically 10 profiles
    # We proactively delete if at limit
    if len(profiles) >= 10:
        print(f"Profile limit ({len(profiles)}/10), deleting oldest...")
        profiles_sorted = sorted(profiles, key=lambda p: p.get("created_at", ""))
        oldest = profiles_sorted[0]
        oldest_uuid = oldest.get("uuid")
        print(f"  Deleting: {oldest.get('title')} ({oldest_uuid[:8]}...)")
        api_post("/api/profiles/stop", {"uuid": oldest_uuid}, timeout=5)
        time.sleep(1)
        del_resp = api_post("/api/v2/profiles/delete", {"uuids": [oldest_uuid]})
        if del_resp.get("success"):
            print(f"  ✓ Deleted")
            return True
        else:
            print(f"  ✗ Delete failed: {del_resp}")
            return False
    return True


def create_profile(title, os_type="android", proxy_url=None, noise=True, tags=None, auto_delete_oldest=True, language="en-US"):
    """
    Create a profile with optional auto-cleanup if limit reached.
    
    Args:
        title: Profile name
        os_type: 'android', 'win', or 'mac'
        proxy_url: Optional proxy URL
        noise: Enable fingerprint noise
        tags: List of tags
        auto_delete_oldest: Delete oldest profile if limit reached
        language: Browser language (default: en-US for English)
    
    Returns:
        dict with 'uuid' on success, or 'error' on failure
    """
    os_arch = "arm" if os_type in ["mac", "android"] else "x86"
    
    # Ensure slot available
    if auto_delete_oldest:
        ensure_profile_slot()
    
    # Get boilerplate
    resp = api_post("/api/v2/profiles/boilerplate/quick", {"os": os_type, "os_arch": os_arch, "count": 1})
    if not resp.get("success"):
        return {"error": f"Boilerplate failed: {resp}"}
    
    bp = resp["data"]["boilerplates"][0]
    fp = bp["fp"]
    if fp.get("dns") is None:
        fp["dns"] = ""
    if noise:
        fp["noise"] = {"webgl": True, "canvas": True, "audio": True, "client_rects": True}
    fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}
    
    # Set browser language to English
    # Format: {"type": "manual", "data": ["en-US", "en"]} or {"type": "ip", "data": None}
    if language:
        fp["languages"] = {"type": "manual", "data": [language, language.split("-")[0]]}
    
    storage_opts = bp.get("storage_options", {})
    if os_type == "android":
        storage_opts["extensions"] = False
    
    proxy_config = parse_proxy_url(proxy_url) if proxy_url else {"type": "direct"}
    
    payload = {
        "title": title, "name": title, "description": bp.get("description", ""),
        "start_pages": bp.get("start_pages", []), "bookmarks": bp.get("bookmarks", []),
        "launch_args": bp.get("launch_args", []), "logo": bp.get("logo", ""),
        "tags": tags or [],
        "fp": fp, "proxy": proxy_config, "proxies": bp.get("proxies", []),
        "local_cache": False, "storage_options": storage_opts,
        "extensions": [],
    }
    
    resp = api_post("/api/v2/profiles", payload)
    
    # If failed due to limit, try deleting oldest and retry
    if not resp.get("success") and auto_delete_oldest:
        error_msg = str(resp.get("message", resp.get("error", "")))
        if "limit" in error_msg.lower() or "maximum" in error_msg.lower():
            print("Profile limit hit, deleting oldest...")
            list_resp = api_post("/api/v2/profiles/list")
            if list_resp.get("success"):
                profiles = list_resp.get("data", {}).get("profiles", [])
                if profiles:
                    profiles_sorted = sorted(profiles, key=lambda p: p.get("created_at", ""))
                    oldest = profiles_sorted[0]
                    api_post("/api/profiles/stop", {"uuid": oldest["uuid"]}, timeout=5)
                    time.sleep(1)
                    api_post("/api/v2/profiles/delete", {"uuids": [oldest["uuid"]]})
                    print(f"  Deleted: {oldest.get('title')}")
                    # Retry
                    resp = api_post("/api/v2/profiles", payload)
    
    if resp.get("success"):
        return {"uuid": resp["data"]["uuid"], "fp": fp}
    return {"error": str(resp)}


def cmd_create(args):
    """Create a new profile"""
    title = args.title
    os_type = args.os
    os_arch = "arm" if os_type in ["mac", "android"] else "x86"
    print(f"Creating {os_type.upper()} profile: {title}")

    resp = api_post("/api/v2/profiles/boilerplate/quick", {"os": os_type, "os_arch": os_arch, "count": 1})
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    if not resp.get("success"):
        print(f"Error: {resp}")
        return 1

    bp = resp["data"]["boilerplates"][0]
    fp = bp["fp"]
    if fp.get("dns") is None:
        fp["dns"] = ""
    if args.noise:
        fp["noise"] = {"webgl": True, "canvas": True, "audio": True, "client_rects": True}
    fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}

    storage_opts = bp.get("storage_options", {})
    if os_type == "android":
        storage_opts["extensions"] = False

    proxy_config = {"type": "direct"}
    if args.proxy:
        proxy_config = parse_proxy_url(args.proxy) or proxy_config

    payload = {
        "title": title, "name": title, "description": bp.get("description", ""),
        "start_pages": bp.get("start_pages", []), "bookmarks": bp.get("bookmarks", []),
        "launch_args": bp.get("launch_args", []), "logo": bp.get("logo", ""),
        "tags": args.tags.split(",") if args.tags else [],
        "fp": fp, "proxy": proxy_config, "proxies": bp.get("proxies", []),
        "local_cache": bp.get("local_cache", False), "storage_options": storage_opts,
        "extensions": [],
    }

    resp = api_post("/api/v2/profiles", payload)
    if resp.get("success"):
        uuid = resp["data"]["uuid"]
        print(f"\n✓ Created: {uuid}")
        if args.start:
            args.uuid = uuid
            return cmd_start(args)
        return 0
    print(f"\n✗ Error: {resp}")
    return 1


def cmd_start(args):
    """Start a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    print(f"Starting profile: {uuid[:16]}...")
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(1)
    resp = api_post("/api/profiles/start", {"uuid": uuid, "debug_port": True, "headless": getattr(args, "headless", False)}, timeout=30)
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    if resp.get("state") == "STARTED":
        print(f"\n✓ Profile started!")
        print(f"  WebSocket: {resp.get('ws_endpoint')}")
        print(f"  DevTools: http://localhost:{resp.get('debug_port')}")
        return 0
    print(f"\n✗ Failed: {resp}")
    return 1


def cmd_stop(args):
    """Stop profile(s)"""
    if args.all:
        resp = api_get("/api/profiles/active")
        if not resp or resp.get("error"):
            print("No active profiles.")
            return 0
        for p in resp:
            api_post("/api/profiles/stop", {"uuid": p.get("uuid")}, timeout=5)
        print(f"✓ Stopped {len(resp)} profiles")
        return 0
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=10)
    print("✓ Stop request sent")
    return 0


def cmd_delete(args):
    """Delete a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    if not args.force:
        if input(f"Delete {uuid[:16]}...? [y/N]: ").lower() != "y":
            return 0
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(1)
    resp = api_post("/api/v2/profiles/delete", {"uuids": [uuid]})
    print("✓ Deleted" if resp.get("success") else f"✗ Error: {resp}")
    return 0 if resp.get("success") else 1


def cmd_purge(args):
    """Delete ALL profiles"""
    resp = api_post("/api/v2/profiles/list")
    profiles = resp.get("data", {}).get("profiles", [])
    if not profiles:
        print("No profiles to delete.")
        return 0
    if not args.force and input(f"Delete ALL {len(profiles)} profiles? [y/N]: ").lower() != "y":
        return 0
    for p in profiles:
        api_post("/api/profiles/stop", {"uuid": p["uuid"]}, timeout=5)
    time.sleep(2)
    resp = api_post("/api/v2/profiles/delete", {"uuids": [p["uuid"] for p in profiles]}, timeout=30)
    print(f"✓ Deleted {len(profiles)} profiles" if resp.get("success") else f"✗ Error: {resp}")
    return 0 if resp.get("success") else 1


def cmd_info(args):
    """Show profile details"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    resp = api_get(f"/api/v2/profiles/{uuid}")
    if not resp.get("success"):
        print(f"Error: {resp}")
        return 1
    profile = resp["data"]
    if args.json:
        print(json.dumps(profile, indent=2))
        return 0
    fp = profile.get("fp", {})
    print(f"\nProfile: {profile.get('title', 'Untitled')}")
    print(f"UUID: {profile.get('uuid')}")
    print(f"OS: {fp.get('os')} v{fp.get('os_version')}")
    print(f"GPU: {fp.get('renderer')}")
    return 0


def cmd_clone(args):
    """Clone a profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    resp = api_post(f"/api/v2/profiles/{uuid}/clone", {"amount": args.count})
    if resp.get("success"):
        for c in resp.get("data", []):
            print(f"  {c.get('uuid')} - {c.get('title')}")
        return 0
    print(f"✗ Error: {resp}")
    return 1


def cmd_ip(args):
    """Check IP through profile"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(1)
    resp = api_post("/api/profiles/start", {"uuid": uuid, "debug_port": True}, timeout=30)
    if resp.get("state") != "STARTED":
        print(f"Failed: {resp}")
        return 1
    ws = resp.get("ws_endpoint")
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _():
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(ws)
                ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
                page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                await page.goto("https://ipinfo.io/json", timeout=30000)
                content = await page.content()
                m = re.search(r'\{[^}]+\}', content)
                if m:
                    d = json.loads(m.group())
                    print(f"IP: {d.get('ip')} | {d.get('city')}, {d.get('country')} | {d.get('org')}")

        asyncio.run(_())
    except ImportError:
        print("Install: pip install playwright")
        return 1
    finally:
        if not args.keep:
            api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    return 0


def cmd_test(args):
    """Test profile on PixelScan"""
    uuid = resolve_uuid(args.uuid)
    if not uuid:
        return 1
    api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    time.sleep(2)
    resp = api_post("/api/profiles/start", {"uuid": uuid, "debug_port": True}, timeout=30)
    if resp.get("state") != "STARTED":
        print(f"Failed: {resp}")
        return 1
    ws = resp.get("ws_endpoint")
    try:
        import asyncio
        from playwright.async_api import async_playwright

        async def _():
            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(ws)
                ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
                page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                await page.goto("https://www.google.com", timeout=30000)
                await asyncio.sleep(2)
                await page.goto("https://pixelscan.net/fingerprint-check", timeout=60000)
                await asyncio.sleep(12)
                text = await page.evaluate("() => document.body.innerText")
                print("Masking: ✓ PASS" if "No masking detected" in text else "Masking: ✗ FAIL")

        asyncio.run(_())
    except ImportError:
        print("Install: pip install playwright")
        return 1
    finally:
        if not args.keep:
            api_post("/api/profiles/stop", {"uuid": uuid}, timeout=5)
    return 0


def cmd_templates(args):
    """List profile templates"""
    resp = api_get("/api/v2/templates")
    if resp.get("error"):
        print(f"Error: {resp['error']}")
        return 1
    items = resp.get("data", {}).get("items", [])
    total = resp.get("data", {}).get("total", 0)
    if not items:
        print("No templates found.")
        return 0
    if args.json:
        print(json.dumps(items, indent=2))
        return 0
    print(f"\n{'Name':<20} {'OS':<10} {'Arch':<8} {'UUID'}")
    print("-" * 70)
    for t in items:
        name = (t.get("name") or "Untitled")[:18]
        os_type = t.get("os", "?")
        arch = t.get("os_arch", "?")
        print(f"{name:<20} {os_type:<10} {arch:<8} {t.get('uuid', '')}")
    print(f"\nTotal: {total} template(s)")
    return 0


def cmd_boilerplate(args):
    """Get fingerprint boilerplate"""
    resp = api_post("/api/v2/profiles/boilerplate/quick", {"os": args.os, "os_arch": "arm" if args.os in ["mac", "android"] else "x86", "count": args.count})
    if not resp.get("success"):
        print(f"Error: {resp}")
        return 1
    if args.json:
        print(json.dumps(resp["data"]["boilerplates"], indent=2))
        return 0
    for i, bp in enumerate(resp["data"]["boilerplates"]):
        fp = bp["fp"]
        print(f"\n{i+1}. {bp.get('name')} | {fp.get('os')} v{fp.get('os_version')} | {fp.get('screen')} | {fp.get('renderer')}")
    return 0


def register_api_commands(sub, OCTO_DEFAULT_PORT):
    """Register all API subcommands"""
    def reg(name, *aliases, func=None, help=None):
        p = sub.add_parser(name, aliases=list(aliases), help=help)
        if func:
            p.set_defaults(func=func)
        return p

    reg("status", func=cmd_status, help="Show OctoBrowser status")
    reg("version", func=cmd_version, help="Show version info")
    
    p = reg("list", "ls", func=cmd_list, help="List all profiles")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    
    p = reg("active", func=cmd_active, help="List running profiles")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    
    p = reg("create", "new", func=cmd_create, help="Create a new profile")
    p.add_argument("title", help="Profile name")
    p.add_argument("--os", choices=["android", "win", "mac"], default="android", help="OS type (default: android)")
    p.add_argument("--proxy", help="Proxy URL (http://user:pass@host:port)")
    p.add_argument("--tags", help="Comma-separated tags")
    p.add_argument("--noise", action="store_true", default=True, help="Enable fingerprint noise (default)")
    p.add_argument("--no-noise", action="store_false", dest="noise", help="Disable fingerprint noise")
    p.add_argument("--start", action="store_true", help="Start profile after creation")
    p.add_argument("--headless", action="store_true", help="Start in headless mode")
    
    p = reg("start", func=cmd_start, help="Start a profile")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("--headless", action="store_true", help="Start in headless mode")
    
    p = reg("stop", func=cmd_stop, help="Stop profile(s)")
    p.add_argument("uuid", nargs="?", help="Profile UUID (or prefix)")
    p.add_argument("--all", action="store_true", help="Stop all running profiles")
    
    p = reg("delete", "rm", func=cmd_delete, help="Delete a profile")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    
    p = reg("purge", func=cmd_purge, help="Delete ALL profiles")
    p.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    
    p = reg("info", "show", func=cmd_info, help="Show profile details")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    
    p = reg("clone", func=cmd_clone, help="Clone a profile")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("-n", "--count", type=int, default=1, help="Number of clones")
    
    p = reg("ip", func=cmd_ip, help="Check IP through profile")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("--keep", action="store_true", help="Keep profile running after check")
    
    p = reg("test", func=cmd_test, help="Test profile on PixelScan")
    p.add_argument("uuid", help="Profile UUID (or prefix)")
    p.add_argument("--keep", action="store_true", help="Keep profile running after test")
    
    p = reg("templates", "tpl", func=cmd_templates, help="List profile templates")
    p.add_argument("--json", action="store_true", help="Output as JSON")

    p = reg("boilerplate", "bp", func=cmd_boilerplate, help="Get fingerprint boilerplate")
    p.add_argument("--os", choices=["android", "win", "mac"], default="android", help="OS type (default: android)")
    p.add_argument("-n", "--count", type=int, default=1, help="Number of boilerplates")
    p.add_argument("--json", action="store_true", help="Output as JSON")


if __name__ == "__main__":
    import argparse
    import sys
    from config import OCTO_DEFAULT_PORT

    parser = argparse.ArgumentParser(
        description="OctoBrowser API CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    register_api_commands(sub, OCTO_DEFAULT_PORT)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    sys.exit(args.func(args))
