#!/usr/bin/env python3
"""
OctoBrowser API CLI commands.

Profile management, status, and automation commands.
"""

import json
import re
import time
import requests
from urllib.parse import urlparse, unquote

from config import get_octo_port

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
    def reg(name, *aliases, func=None, **kwargs):
        p = sub.add_parser(name, aliases=list(aliases), **kwargs)
        if func:
            p.set_defaults(func=func)
        return p

    reg("status", func=cmd_status)
    reg("version", func=cmd_version)
    
    p = reg("list", "ls", func=cmd_list)
    p.add_argument("--json", action="store_true")
    
    p = reg("active", func=cmd_active)
    p.add_argument("--json", action="store_true")
    
    p = reg("create", "new", func=cmd_create)
    p.add_argument("title")
    p.add_argument("--os", choices=["android", "win", "mac"], default="android")
    p.add_argument("--proxy")
    p.add_argument("--tags")
    p.add_argument("--noise", action="store_true", default=True)
    p.add_argument("--no-noise", action="store_false", dest="noise")
    p.add_argument("--start", action="store_true")
    p.add_argument("--headless", action="store_true")
    
    p = reg("start", func=cmd_start)
    p.add_argument("uuid")
    p.add_argument("--headless", action="store_true")
    
    p = reg("stop", func=cmd_stop)
    p.add_argument("uuid", nargs="?")
    p.add_argument("--all", action="store_true")
    
    p = reg("delete", "rm", func=cmd_delete)
    p.add_argument("uuid")
    p.add_argument("-f", "--force", action="store_true")
    
    p = reg("purge", func=cmd_purge)
    p.add_argument("-f", "--force", action="store_true")
    
    p = reg("info", "show", func=cmd_info)
    p.add_argument("uuid")
    p.add_argument("--json", action="store_true")
    
    p = reg("clone", func=cmd_clone)
    p.add_argument("uuid")
    p.add_argument("-n", "--count", type=int, default=1)
    
    p = reg("ip", func=cmd_ip)
    p.add_argument("uuid")
    p.add_argument("--keep", action="store_true")
    
    p = reg("test", func=cmd_test)
    p.add_argument("uuid")
    p.add_argument("--keep", action="store_true")
    
    p = reg("boilerplate", "bp", func=cmd_boilerplate)
    p.add_argument("--os", choices=["android", "win", "mac"], default="android")
    p.add_argument("-n", "--count", type=int, default=1)
    p.add_argument("--json", action="store_true")
