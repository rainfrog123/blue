# %% [markdown]
# # Stripe URL Extractor
# 
# Iterates through sessions.json, injects cookies, and extracts Stripe URLs.
# Only extracts for accounts with "Free 7-day trial" option (skips "Start Pro" only).
#
# **Usage:**
# - Run cells in order (Shift+Enter)
# - Updates info.json with extracted stripe_url

# %% [1] Initialize & Configure
import json
import os
import random
import subprocess
import time
import asyncio
from urllib.parse import quote
from playwright.async_api import async_playwright

from api_client import get_api, api_get, api_post, create_profile
from config import CONFIG, verify_paths

# === CONFIGURATION ===
PROFILE_OS = "mac"  # android, win, mac
DEBUG_PORT = 6395   # Fixed debug port
SOCKS_PROXY = "socks5://100.116.72.20:7890"

# === SESSION STATE ===
playwright = None
browser = None
context = None
page = None
profile_uuid = None
ws_endpoint = None
debug_port = None

# === HUMAN-LIKE HELPERS ===
async def scroll_into_view(element, page_ref=None):
    """Scroll element into view with human-like behavior."""
    p = page_ref or page
    await element.scroll_into_view_if_needed()
    await asyncio.sleep(random.uniform(0.2, 0.5))


async def human_click(element, page_ref=None, hover_first=True):
    """Human-like click: scroll into view, hover, pause, then click."""
    p = page_ref or page
    await scroll_into_view(element, p)
    
    box = await element.bounding_box()
    if box:
        x = box["x"] + box["width"] * random.uniform(0.25, 0.75)
        y = box["y"] + box["height"] * random.uniform(0.25, 0.75)
        await p.mouse.move(x, y)
        if hover_first:
            await asyncio.sleep(random.uniform(0.15, 0.4))
        await asyncio.sleep(random.uniform(0.08, 0.2))
        await p.mouse.down()
        await asyncio.sleep(random.uniform(0.05, 0.12))
        await p.mouse.up()
    else:
        await element.click()


async def human_mouse_moves(page_ref=None, count=None):
    """Random mouse movements as if reading/scanning the page."""
    p = page_ref or page
    viewport = p.viewport_size
    if not viewport:
        return
    vw, vh = viewport["width"], viewport["height"]
    n = count or random.randint(2, 4)
    for _ in range(n):
        rand_x = random.randint(int(vw * 0.2), int(vw * 0.8))
        rand_y = random.randint(int(vh * 0.2), int(vh * 0.6))
        await p.mouse.move(rand_x, rand_y)
        await asyncio.sleep(random.uniform(0.4, 1.0))


# === VERIFY ENVIRONMENT ===
print("Verifying paths...")
if not verify_paths():
    raise RuntimeError("Missing required files")

resp = api_get("/api/v2/client/themes", timeout=3)
if resp.get("error"):
    raise RuntimeError(f"OctoBrowser not running: {resp['error']}")

print(f"✓ OctoBrowser API: {get_api()}")
print(f"\nConfig: {PROFILE_OS} | Port: {DEBUG_PORT} | Proxy: {SOCKS_PROXY}")


# %% [2] Load Sessions & Info
auto_dir = os.environ.get("AUTO_DIR") or os.path.dirname(os.path.abspath(__file__))
session_file = os.path.join(auto_dir, "sessions.json")
info_file = os.path.join(auto_dir, "info.json")

try:
    with open(session_file) as f:
        sessions = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    raise RuntimeError(f"Failed to load sessions.json: {e}")

try:
    with open(info_file) as f:
        infos = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    infos = []

if not sessions:
    raise RuntimeError("No sessions found in sessions.json")

# Find sessions missing info: no entry, missing email, or missing stripe_url
pending = []
new_entries = 0
missing_data = 0

for i, session in enumerate(sessions):
    token = session.get("workos_session_token", "")
    if not token:
        continue
    
    # Check if info entry exists and is complete
    if i >= len(infos):
        pending.append((i, token, True))  # True = new entry
        new_entries += 1
    else:
        info = infos[i]
        needs_email = not (info.get("email") or "").strip()
        trial_status = (info.get("trial_status") or "").strip()
        needs_trial_status = not trial_status
        # stripe_url only needed when can_trial; already_trial/expired = done
        needs_stripe = (
            not (info.get("stripe_url") or "").strip()
            and trial_status not in ("already_trial", "expired")
        )
        if needs_email or needs_stripe or needs_trial_status:
            pending.append((i, token, False))
            missing_data += 1

print(f"✓ Loaded {len(sessions)} sessions, {len(infos)} info records")
print(f"  New entries to create: {new_entries}")
print(f"  Missing email/stripe: {missing_data}")
print(f"  Total pending: {len(pending)}")

if not pending:
    raise RuntimeError("All sessions already have complete info!")

# Select session: SESSION_INDEX env = session index in sessions.json, else random from pending
session_index_env = os.environ.get("SESSION_INDEX")
if session_index_env is not None:
    try:
        want_idx = int(session_index_env)
        found = [j for j, (si, _, _) in enumerate(pending) if si == want_idx]
        if found:
            selected_idx = found[0]
        else:
            # Session already complete, nothing to do
            print(f"\n✓ Session {want_idx} already complete, skipping")
            raise SystemExit(0)
    except (ValueError, IndexError):
        selected_idx = random.randint(0, len(pending) - 1)
else:
    selected_idx = random.randint(0, len(pending) - 1)

session_idx, session_token, is_new_entry = pending[selected_idx]
print(f"\n✓ Selected session: index {session_idx} (pending #{selected_idx + 1}/{len(pending)})")


# %% [3] Create Profile
title = f"StripeExtract-{PROFILE_OS.title()}-{int(time.time())}"

result = create_profile(
    title=title,
    os_type=PROFILE_OS,
    proxy_url=SOCKS_PROXY,
    noise=True,
    auto_delete_oldest=True
)

if result.get("error"):
    raise RuntimeError(result["error"])

profile_uuid = result["uuid"]
fp = result.get("fp", {})

print(f"\n✓ Created: {title}")
print(f"  UUID: {profile_uuid}")
print(f"  OS: {fp.get('os')} v{fp.get('os_version')}")


# %% [4] Start Profile
print(f"Starting: {profile_uuid[:16]}...")

# Kill any process using the debug port
if isinstance(DEBUG_PORT, int):
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{DEBUG_PORT}"],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                subprocess.run(["kill", "-9", pid], capture_output=True)
            print(f"  Killed process(es) on port {DEBUG_PORT}: {pids}")
            time.sleep(1)
    except Exception as e:
        print(f"  Port check failed: {e}")

api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
time.sleep(2)

resp = api_post(
    "/api/profiles/start",
    {"uuid": profile_uuid, "debug_port": DEBUG_PORT},
    timeout=30
)

ws_endpoint = resp.get("ws_endpoint")
debug_port = resp.get("debug_port")

print(f"\n✓ Started!")
print(f"  WebSocket: {ws_endpoint}")
print(f"  DevTools: http://localhost:{debug_port}")

if PROFILE_OS == "android":
    time.sleep(3)


# %% [5] Connect Playwright
playwright = await async_playwright().start()
browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
context = browser.contexts[0]
page = context.pages[0] if context.pages else await context.new_page()

print(f"✓ Connected!")
print(f"  URL: {page.url}")


# %% [6] Debug Helper
async def debug_page():
    """Screenshot and print state"""
    print("=" * 50)
    print(f"Profile: {profile_uuid[:16]}... ({PROFILE_OS})")
    print(f"DevTools: http://localhost:{debug_port}")
    print(f"URL: {page.url}")
    print(f"Title: {await page.title()}")
    print(f"Tabs: {len(context.pages)}")
    await page.screenshot(path="/tmp/debug.png")
    print(f"Screenshot: /tmp/debug.png")
    print("=" * 50)


# %% [7] Extract Stripe URL (single random session)
print(f"\n{'='*50}")
print(f"Processing session index: {session_idx}")
print("=" * 50)

# Clear existing cookies and storage
await context.clear_cookies()

# Clear localStorage/sessionStorage for clean state
try:
    await page.goto("https://cursor.com", timeout=15000)
    await page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
except:
    pass

# Set the session cookie
await context.add_cookies([{
    "name": "WorkosCursorSessionToken",
    "value": session_token,
    "domain": ".cursor.com",
    "path": "/",
    "httpOnly": True,
    "secure": True,
    "sameSite": "Lax"
}])
print(f"✓ Cookie set ({len(session_token)} chars)")

# Navigate to dashboard
await page.goto("https://cursor.com/dashboard", timeout=30000)
await page.wait_for_load_state("load")
await asyncio.sleep(random.uniform(2, 3))

print(f"  URL: {page.url}")

# Result tracking
result_status = None
stripe_url = None
extracted_email = ""

# Check if redirected to login (session expired)
if "login" in page.url or "signin" in page.url or "auth" in page.url:
    print("✗ Session expired")
    result_status = "expired"
else:
    # Extract email from dashboard sidebar (div[title*="@"] or p with email)
    try:
        email_div = page.locator('div[title*="@"]')
        if await email_div.count() > 0:
            extracted_email = (await email_div.first.get_attribute("title") or "").strip()
        if not extracted_email:
            email_p = page.locator('div.min-w-0 p.text-base.font-medium')
            if await email_p.count() > 0:
                extracted_email = (await email_p.first.text_content() or "").strip()
        if extracted_email:
            print(f"✓ Extracted email: {extracted_email}")
    except Exception as e:
        print(f"  Email extraction failed: {e}")
    
    # Human-like page scan
    await human_mouse_moves(count=2)
    await asyncio.sleep(random.uniform(0.5, 1))
    
    # Check for "Free 7-day trial" button (Pro plan card; exclude disabled "Processing...")
    trial_btn = page.locator('button:has-text("Free 7-day trial"):not([disabled])').or_(
        page.get_by_role("button", name="Free 7-day trial")
    ).or_(
        page.locator('button:has(svg.lucide-gift):not([disabled])')
    )
    
    # Check for "Start Pro Now" (already on trial, no need to extract)
    pro_btn = page.locator('button:has-text("Start Pro Now")').or_(
        page.get_by_role("button", name="Start Pro Now")
    )
    
    has_trial = await trial_btn.count() > 0
    has_pro_only = await pro_btn.count() > 0 and not has_trial
    
    if has_pro_only:
        print("✗ Already on Pro Trial (Start Pro Now button) - skipped")
        result_status = "already_trial"
    elif not has_trial:
        # Check if "Processing..." (button disabled, mid-flow) - wait for Stripe
        processing = page.locator('button:has-text("Processing...")')
        if await processing.count() > 0:
            print("? Button shows Processing... - waiting for Stripe")
            initial_pages = len(context.pages)
            for _ in range(30):
                await asyncio.sleep(0.5)
                if len(context.pages) > initial_pages:
                    stripe_tab = context.pages[-1]
                    url = stripe_tab.url
                    if "stripe" in url or "checkout" in url:
                        stripe_url = url
                        print(f"✓ Stripe tab: {stripe_url}")
                        await stripe_tab.close()
                        break
                if "stripe" in page.url or "checkout" in page.url:
                    stripe_url = page.url
                    print(f"✓ Stripe redirect: {stripe_url}")
                    break
            result_status = "success" if stripe_url else "no_redirect"
        else:
            print("? No trial button found")
            await page.screenshot(path=f"/tmp/stripe_check_{session_idx}.png")
            result_status = "no_button"
    else:
        # Click trial button
        initial_pages = len(context.pages)
        
        try:
            await trial_btn.first.wait_for(state="visible", timeout=5000)
            await human_click(trial_btn.first)
            print("✓ Clicked 'Free 7-day trial'")
            
            # Wait for Stripe tab/redirect
            for _ in range(30):
                await asyncio.sleep(0.5)
                
                # Check for new tab (Stripe popup)
                if len(context.pages) > initial_pages:
                    stripe_tab = context.pages[-1]
                    url = stripe_tab.url
                    if "stripe" in url or "checkout" in url:
                        stripe_url = url
                        print(f"✓ Stripe tab: {stripe_url}")
                        await stripe_tab.close()
                        break
                
                # Check if current page redirected to Stripe
                if "stripe" in page.url or "checkout" in page.url:
                    stripe_url = page.url
                    print(f"✓ Stripe redirect: {stripe_url}")
                    break
            
            if stripe_url:
                result_status = "success"
            else:
                print("? No Stripe URL detected")
                await page.screenshot(path=f"/tmp/stripe_fail_{session_idx}.png")
                result_status = "no_redirect"
                
        except Exception as e:
            print(f"✗ Failed to click trial button: {e}")
            result_status = "click_failed"

# Map result_status to trial_status (critical: can_trial vs no_trial)
# can_trial = Free 7-day trial button available
# already_trial = Start Pro Now (on Pro Trial)
# expired = session expired
# no_trial = no trial button found
trial_status_map = {
    "success": "can_trial",
    "already_trial": "already_trial",
    "expired": "expired",
    "no_button": "no_trial",
    "no_redirect": "can_trial",  # had trial button, Stripe didn't open
    "click_failed": "can_trial",  # had trial button
}
trial_status = trial_status_map.get(result_status, "no_trial")

# Always save when we have a result (email, stripe_url, or trial_status)
if result_status and (extracted_email or stripe_url or trial_status):
    while len(infos) <= session_idx:
        infos.append({})
    
    if is_new_entry or not infos[session_idx]:
        infos[session_idx] = {
            "email": extracted_email or "",
            "phone": infos[session_idx].get("phone", "") if session_idx < len(infos) else "",
            "stripe_url": stripe_url or "",
            "trial_status": trial_status,
            "workos_session_token": session_token,
            "profile_uuid": "",
            "activation_id": "",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "profile_os": "",
            "proxy_used": None,
        }
        print(f"✓ Created new info entry")
    else:
        if extracted_email:
            infos[session_idx]["email"] = extracted_email
        if stripe_url:
            infos[session_idx]["stripe_url"] = stripe_url
        infos[session_idx]["trial_status"] = trial_status
        print(f"✓ Updated info.json")
    
    with open(info_file, "w") as f:
        json.dump(infos, f, indent=2)


# %% [8] Summary
print(f"\n{'='*50}")
print("RESULT")
print("=" * 50)
print(f"Session index: {session_idx}")
print(f"Status: {result_status}")
print(f"Trial: {trial_status}")
if extracted_email:
    print(f"Email: {extracted_email}")
if stripe_url:
    print(f"Stripe URL: {stripe_url}")
print(f"Remaining pending: {len(pending) - 1}")


# %% [9] Cleanup
print("\nCleaning up...")

if browser:
    await browser.close()

if playwright:
    await playwright.stop()

if profile_uuid:
    api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
    print(f"  Profile stopped")

print("✓ Done")
