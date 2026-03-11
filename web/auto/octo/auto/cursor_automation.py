# %% [markdown]
# # Cursor Account Automation
# 
# Run cells sequentially to create a Cursor account.
# Uses cli.py for all OctoBrowser operations.
#
# **Usage:**
# - Run cells in order (Shift+Enter)
# - Run `await debug_page()` to check state

# %% [1] Initialize & Configure
import json
import os
import random
import string
import subprocess
import sys
import time
import asyncio
from urllib.parse import unquote
from playwright.async_api import async_playwright

WORKER_PATH = "/allah/blue/web/auto/worker"
if WORKER_PATH not in sys.path:
    sys.path.insert(0, WORKER_PATH)
from otp_catcher import get_otp

from api_cli import get_api, api_get, api_post, parse_proxy_url, create_profile
from config import CONFIG, verify_paths
from cursor_helpers import (
    poll_sms_code_async, get_active_activations,
    get_phone_number, get_existing_phone_number, format_phone_uk,
    resend_sms, cancel_sms,
    fill_otp, set_react_input
)

# === CONFIGURATION ===
PROFILE_OS = "mac"  # android, win, mac
USE_PROXY = False
PROXY_URL = "https://user-sp19qgy7m9-country-de-session-32c2d04dcd49-sessionduration-60:+26iSboeQ0wUyx4qEw@de.decodo.com:48999"
DEBUG_PORT = 6393  # Fixed debug port (or True for auto-assign)

USE_EXISTING_PHONE = True   # True = reuse already activated phone, False = purchase new
PHONE_ACTIVATION_INDEX = 0  # Which activation to use (0 = newest)

# === SESSION STATE ===
playwright = None
browser = None
context = None
page = None
profile_uuid = None
ws_endpoint = None
debug_port = None
email = None
phone = None
phone_local = None
activation_id = None
stripe_url = None
session_token = None

# === VERIFY ENVIRONMENT ===
print("Verifying paths...")
if not verify_paths():
    raise RuntimeError("Missing required files")

resp = api_get("/api/v2/client/themes", timeout=3)
if resp.get("error"):
    raise RuntimeError(f"OctoBrowser not running: {resp['error']}")

print(f"✓ OctoBrowser API: {get_api()}")
print(f"\nConfig: {PROFILE_OS} | Proxy: {'ON' if USE_PROXY else 'OFF'} | Port: {DEBUG_PORT}")
print(f"Phone: {'EXISTING' if USE_EXISTING_PHONE else 'NEW'} (index: {PHONE_ACTIVATION_INDEX})")


# %% [3] Create Profile
title = f"Cursor-{PROFILE_OS.title()}-{int(time.time())}"
proxy = PROXY_URL if USE_PROXY else None

result = create_profile(
    title=title,
    os_type=PROFILE_OS,
    proxy_url=proxy,
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
print(f"  GPU: {fp.get('renderer')}")


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

if PROFILE_OS == "android":
    await page.goto("https://www.google.com", timeout=30000)
    await asyncio.sleep(2)


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


# %% [7] Navigate to cursor.com (fresh session)
# Clear cookies to ensure fresh login state
await context.clear_cookies()
print("✓ Cleared cookies")

await page.goto("https://cursor.com")
await page.wait_for_load_state("networkidle")
await asyncio.sleep(2)
print(f"✓ Loaded: {await page.title()}")


# %% [8] Click Sign In
initial_tabs = len(context.pages)

# Try multiple selectors for sign in button
sign_in = page.get_by_role("link", name="Sign in").or_(
    page.get_by_text("Sign in", exact=True)
).or_(
    page.locator('a[href*="signin"]')
).or_(
    page.locator('a[href*="login"]')
)

try:
    await sign_in.wait_for(state="visible", timeout=15000)
except Exception as e:
    # Debug: take screenshot and show page content
    await page.screenshot(path="/tmp/signin_error.png")
    print(f"✗ Sign in button not found. Screenshot: /tmp/signin_error.png")
    print(f"  URL: {page.url}")
    print(f"  Title: {await page.title()}")
    raise RuntimeError(f"Sign in button not visible: {e}")

await sign_in.evaluate("el => el.click()")

for _ in range(20):
    await asyncio.sleep(0.5)
    if len(context.pages) > initial_tabs:
        break

if len(context.pages) > initial_tabs:
    page = context.pages[-1]
    auth_url = page.url
    print(f"✓ Auth tab: {auth_url}")
    
    # Force English UI by adding ui_locales parameter
    if "ui_locales" not in auth_url:
        separator = "&" if "?" in auth_url else "?"
        auth_url_en = f"{auth_url}{separator}ui_locales=en"
        await page.goto(auth_url_en)
        print(f"  → Forced English: {page.url}")

await asyncio.sleep(2)


# %% [9] Enter Email
# Generate random unique email to avoid OTP cache conflicts
random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
email = f"{random_id}@hyas.site"

await page.wait_for_selector('input[name="email"]', state="visible", timeout=30000)
email_input = page.locator('input[name="email"]')
await email_input.click()
await email_input.fill(email)

await asyncio.sleep(0.5)
btn = page.locator('button[type="submit"]').or_(
    page.get_by_role("button", name="Continue")
)
await btn.click()

print(f"✓ Email: {email}")


# %% [10] Select Email Code
await asyncio.sleep(2)

btn = page.get_by_text("Email sign-in code")
await btn.wait_for(state="visible", timeout=30000)
await btn.click()
await asyncio.sleep(3)

print("✓ Email code option selected")


# %% [11] Fill Email OTP (otp_catcher / hyas-mail worker)
print(f"Polling for email code: {email}")
otp = None
for i in range(60):  # 300s timeout, 5s interval
    data = get_otp(email)
    if data:
        otp = data.get("otp")
        print(f"OTP received: {otp}")
        break
    print(f"  [{(i + 1) * 5}s] waiting...")
    await asyncio.sleep(5)

if otp:
    await fill_otp(page, otp)
    print(f"✓ OTP: {otp}")
else:
    print("Timeout. Manual: otp = '123456'; await fill_otp(page, otp)")


# %% [12] Wait for Phone Page
await asyncio.sleep(8)
print(f"✓ Phone page: {page.url}")


# %% [12.5] List Active Phone Activations (optional - run to see available)
activations = get_active_activations()
if activations:
    print(f"\nSet PHONE_ACTIVATION_INDEX to choose which to use (currently: {PHONE_ACTIVATION_INDEX})")


# %% [13] Get Phone Number
if USE_EXISTING_PHONE:
    activation_id, phone, phone_local = get_existing_phone_number(PHONE_ACTIVATION_INDEX)
else:
    activation_id, phone, phone_local = get_phone_number()
print(f"✓ Phone: +{phone}")


# %% [14] Fill Phone
await asyncio.sleep(2)

phone_formatted = format_phone_uk(phone_local)
country_code = CONFIG["phone_country_code"]

await set_react_input(page, 'input[name="country_code"]', country_code)
await asyncio.sleep(0.5)
await set_react_input(page, 'input[name="local_number"]', phone_formatted)

print(f"✓ Filled: +{country_code} {phone_formatted}")


# %% [15] Send SMS (with retry on "not available")
MAX_PHONE_RETRIES = 5

for phone_attempt in range(MAX_PHONE_RETRIES):
    btn = page.get_by_text("Send verification code")
    await btn.click()
    print(f"✓ SMS requested (attempt {phone_attempt + 1})")
    
    await asyncio.sleep(2)
    
    # Check for "phone not available" error
    error_msg = page.locator('text="This phone number is not available."')
    if await error_msg.count() > 0:
        print(f"✗ Phone rejected: +{phone}")
        
        # Cancel current activation (refund)
        cancel_sms(activation_id)
        print(f"  Cancelled activation {activation_id}")
        
        # Get a NEW phone number (not from existing)
        activation_id, phone, phone_local = get_phone_number()
        print(f"✓ New phone: +{phone}")
        
        # Fill new phone
        phone_formatted = format_phone_uk(phone_local)
        await set_react_input(page, 'input[name="country_code"]', country_code)
        await asyncio.sleep(0.5)
        await set_react_input(page, 'input[name="local_number"]', phone_formatted)
        print(f"  Filled: +{country_code} {phone_formatted}")
        
        await asyncio.sleep(1)
        continue
    
    # No error - SMS sent successfully
    break
else:
    raise RuntimeError(f"Failed to find valid phone after {MAX_PHONE_RETRIES} attempts")


# %% [16] Fill SMS Code
sms_code = await poll_sms_code_async(activation_id)

if sms_code:
    await asyncio.sleep(2)
    await fill_otp(page, sms_code, fallback='input[type="tel"]')
    print(f"✓ SMS: {sms_code}")
    print(f"  (Number kept for reuse - run resend_sms({activation_id}) for new code)")
else:
    print("Timeout - no SMS received.")


# %% [17] Maybe Later (resend: run from here)
# For reusing number on subsequent accounts, request resend first:
resend_sms(activation_id)
print(f"✓ Resend requested for activation {activation_id}")

await asyncio.sleep(2)
btn = page.get_by_text("Maybe Later")
await btn.click()
print("✓ Maybe Later")


# %% [18] Skip for now
await asyncio.sleep(2)
btn = page.get_by_text("Skip for now")
await btn.click()
print("✓ Skip")


# %% [19] Continue 1/2 (disable Share Data)
await asyncio.sleep(2)

# Turn off "Share Data" toggle if it's on
toggle = page.locator('button[role="switch"][data-state="checked"]')
if await toggle.count() > 0:
    await toggle.click()
    print("✓ Share Data: OFF")

btn = page.get_by_text("Continue")
await btn.click()
print("✓ Continue 1/2")


# %% [20] Continue 2/2
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("✓ Continue 2/2")


# %% [21] I'll do this later
await asyncio.sleep(2)
btn = page.get_by_text("I'll do this later")
await btn.click()
print("✓ I'll do this later")


# %% [22] Refresh (commented out)
# await asyncio.sleep(2)
# await page.reload()
# await asyncio.sleep(3)
# print(f"✓ Refreshed: {page.url}")


# %% [23] Get Stripe URL (commented out)
# initial_pages = len(context.pages)
# 
# btn = page.get_by_text("Free 7-day trial")
# await btn.click()
# 
# stripe_url = None
# for _ in range(30):
#     await asyncio.sleep(0.3)
#     
#     if len(context.pages) > initial_pages:
#         stripe_tab = context.pages[-1]
#         stripe_url = stripe_tab.url
#         if "stripe" in stripe_url:
#             print(f"✓ Stripe: {stripe_url}")
#             await stripe_tab.close()
#             break
#     
#     if "stripe" in page.url:
#         stripe_url = page.url
#         print(f"✓ Stripe: {stripe_url}")
#         break


# %% [24] Extract Token
# await page.goto("https://cursor.com/dashboard")
await asyncio.sleep(2)

cookies = await context.cookies()
session_token = None
for cookie in cookies:
    if cookie["name"] == "WorkosCursorSessionToken":
        session_token = cookie["value"]
        break

token_decoded = unquote(session_token) if session_token else None
print(f"✓ Token: {len(token_decoded) if token_decoded else 0} chars")


# %% [25] Save Results
auto_dir = os.path.dirname(__file__)
session_file = os.path.join(auto_dir, "session.json")
info_file = os.path.join(auto_dir, "info.json")

# session.json: tokens only
try:
    with open(session_file) as f:
        sessions = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sessions = []
sessions.append({"workos_session_token": token_decoded or ""})
with open(session_file, "w") as f:
    json.dump(sessions, f, indent=2)

# info.json: complete information
try:
    with open(info_file) as f:
        infos = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    infos = []
infos.append({
    "email": email or "",
    "phone": f"+{phone}" if phone else "",
    "stripe_url": stripe_url or "",
    "workos_session_token": token_decoded or "",
    "profile_uuid": profile_uuid or "",
    "activation_id": activation_id or "",
    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "profile_os": PROFILE_OS,
    "proxy_used": PROXY_URL if USE_PROXY else None,
})
with open(info_file, "w") as f:
    json.dump(infos, f, indent=2)

print(f"\n{'='*50}")
print("RESULTS")
print("=" * 50)
print(f"Email:  {email}")
print(f"Phone:  +{phone}")
print(f"Stripe: {stripe_url}")
print(f"Token:  {token_decoded[:50]}..." if token_decoded else "Token: None")
print("=" * 50)


# %% [26] Cleanup
print("Cleaning up...")

if browser:
    await browser.close()

if playwright:
    await playwright.stop()

if profile_uuid:
    api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
    print(f"  Profile stopped")

print("✓ Done")


# %% [27] Resend SMS (reuse number for another account)
# resend_sms(activation_id)


# %% [28] Emergency: Cancel SMS
# cancel_sms(activation_id)


# %% [29] Emergency: Interrupt kernel to stop polling
# In Jupyter: Kernel > Interrupt (or press 'I' twice)


# %% [30] Test PixelScan
# print("Testing PixelScan...")
# await page.goto("https://pixelscan.net/fingerprint-check", timeout=60000)
# await asyncio.sleep(12)

# text = await page.evaluate("() => document.body.innerText")
# if "No masking detected" in text:
#     print("✓ PASS: No masking")
# elif "Masking detected" in text:
#     print("✗ FAIL: Masking detected")

# await debug_page()
