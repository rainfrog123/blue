# %% [markdown]
# # Cursor Account Automation - Main Workflow
# 
# Run cells sequentially to create a Cursor account.
# Each cell can be debugged independently.
#
# **Prerequisites:** OctoBrowser must be running (Cell 1 will start it if needed)
#
# **Profile Type:** Android (bypasses PixelScan masking detection)
#
# **Usage:**
# - Run cells in order (Shift+Enter in VS Code)
# - If a cell fails, fix and re-run from that cell
# - Use `stop()` from another cell to break polling loops
# - Run `await debug_page()` anytime to see current state
# - Access DevTools at http://localhost:{debug_port}

# %% [1] Initialize - Import & Start OctoBrowser
import os
import time
import asyncio
import requests
from urllib.parse import unquote
from playwright.async_api import async_playwright

# Import our modules
from config import CONFIG, OCTO_API, verify_paths
from octo_helpers import (
    is_octo_running, start_octo_browser, get_api,
    list_profiles, start_profile, stop_profile
)
from cursor_helpers import (
    stop, generate_email, count_available_prefixes,
    poll_email_code, poll_sms_code,
    get_phone_number, format_phone_uk, complete_sms, cancel_sms,
    fill_otp, set_react_input
)

# Verify environment
print("Verifying paths...")
if not verify_paths():
    raise RuntimeError("Missing required files - check paths above")

# Start OctoBrowser if needed
if not start_octo_browser():
    raise RuntimeError("OctoBrowser is required but could not be started")

print(f"\n✓ Ready! OctoBrowser API: {get_api()}")
count_available_prefixes()


# %% [2] Session State - Variables that persist across cells
# These hold state between cells - reset by re-running this cell

playwright = None
browser = None
context = None
page = None

profile_uuid = None
ws_endpoint = None
debug_port = None  # For DevTools access

email = None
phone = None
phone_local = None
activation_id = None

stripe_url = None
session_token = None

# Profile configuration
PROFILE_OS = "android"  # Options: "android", "win", "mac"
                        # Android/Windows bypass PixelScan masking detection

print("Session state initialized (all None)")
print(f"Profile type: {PROFILE_OS}")


# %% [3] Create Profile (Android with Full Noise)
API = get_api()

# List existing profiles
profiles = list_profiles()
print(f"Existing profiles: {len(profiles)}")
for p in profiles[:5]:
    status = "running" if p.get("status") == 6 else "stopped"
    print(f"  - {p['title']} [{p['os']}] ({p['uuid'][:8]}...) [{status}]")
if len(profiles) > 5:
    print(f"  ... and {len(profiles) - 5} more")

# Create new profile with Android fingerprint (bypasses PixelScan masking)
print(f"\n--- Creating {PROFILE_OS.upper()} profile ---")

# Get boilerplate fingerprint
os_arch = "arm" if PROFILE_OS in ["mac", "android"] else "x86"
resp = requests.post(
    f"{API}/api/v2/profiles/boilerplate/quick",
    json={"os": PROFILE_OS, "os_arch": os_arch, "count": 1}
)
bp = resp.json()["data"]["boilerplates"][0]
fp = bp["fp"]

# Print fingerprint details
print(f"\nFingerprint Details:")
print(f"  OS: {fp.get('os')} v{fp.get('os_version')}")
if PROFILE_OS == "android":
    print(f"  Device: {fp.get('device_model')} ({fp.get('device_type')})")
    print(f"  Renderer: {fp.get('renderer')}")
else:
    print(f"  Screen: {fp.get('screen')}")
    print(f"  GPU: {fp.get('renderer')}")
print(f"  User-Agent: {fp.get('user_agent')[:60]}...")

# Fix null dns field
if fp.get("dns") is None:
    fp["dns"] = ""

# Enable full noise (randomizes canvas, webgl, audio hashes)
fp["noise"] = {
    "webgl": True,
    "canvas": True,
    "audio": True,
    "client_rects": True
}
print(f"  Noise: ✓ Full (webgl, canvas, audio, client_rects)")

# Disable WebRTC leaks
fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}
print(f"  WebRTC: ✓ Non-proxied UDP disabled")

# Build payload
title = f"Cursor-{PROFILE_OS.title()}-{int(time.time())}"
storage_opts = bp.get("storage_options", {})

# CRITICAL for Android: extensions must be False
if PROFILE_OS == "android":
    storage_opts["extensions"] = False
    print(f"  Extensions: ✓ Disabled (required for mobile)")

proxy_config = {
    "type": "new",
    "data": {
        "type": "http",
        "ip": "de.decodo.com",
        "port": 48999,
        "login": "user-sp19qgy7m9-country-de-session-32c2d04dcd49-sessionduration-60",
        "password": "+26iSboeQ0wUyx4qEw"
    }
}
print(f"  Proxy: ✓ {proxy_config['data']['ip']}:{proxy_config['data']['port']} (DE)")

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
    "proxy": proxy_config,
    "proxies": bp.get("proxies", []),
    "local_cache": bp.get("local_cache", False),
    "storage_options": storage_opts,
    "extensions": [],
}

resp = requests.post(f"{API}/api/v2/profiles", json=payload)
data = resp.json()

if data.get("success"):
    profile_uuid = data["data"]["uuid"]
    CONFIG["profile_uuid"] = profile_uuid
    print(f"\n✓ Profile created: {title}")
    print(f"  UUID: {profile_uuid}")
else:
    raise RuntimeError(f"Failed to create profile: {data}")


# %% [4] Start Profile & Get WebSocket Endpoint
print(f"Starting profile: {profile_uuid[:8]}...")

# Stop if already running
requests.post(f"{API}/api/profiles/stop", json={"uuid": profile_uuid})
time.sleep(2)

# Start with debug_port enabled
resp = requests.post(
    f"{API}/api/profiles/start",
    json={"uuid": profile_uuid, "debug_port": True}
)
start_data = resp.json()

ws_endpoint = start_data.get("ws_endpoint")
debug_port = start_data.get("debug_port")
browser_pid = start_data.get("browser_pid")

print(f"\n✓ Profile started!")
print(f"  State: {start_data.get('state')}")
print(f"  WebSocket: {ws_endpoint}")
print(f"  Browser PID: {browser_pid}")

print(f"\n--- DevTools Access ---")
print(f"  Debug Port: {debug_port}")
print(f"  DevTools UI: http://localhost:{debug_port}")
print(f"  JSON List:   http://localhost:{debug_port}/json/list")
print(f"  Chrome inspect: chrome://inspect/#devices -> Configure -> localhost:{debug_port}")

# Android needs extra warm-up time
if PROFILE_OS == "android":
    print(f"\n  (Android) Waiting 3s for stability...")
    time.sleep(3)


# %% [5] Connect Playwright to Browser
playwright = await async_playwright().start()
browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
context = browser.contexts[0]

if context.pages:
    page = context.pages[0]
else:
    page = await context.new_page()

print(f"✓ Connected via CDP!")
print(f"  Contexts: {len(browser.contexts)}")
print(f"  Pages: {len(context.pages)}")
print(f"  Current URL: {page.url}")

# For Android, do a warm-up navigation first
if PROFILE_OS == "android":
    print(f"\n  (Android) Warming up with google.com...")
    await page.goto("https://www.google.com", timeout=30000)
    await asyncio.sleep(2)
    print(f"  ✓ Warm-up complete")


# %% [6] Debug Helper - Run anytime to check page state
async def debug_page():
    """Screenshot and print current state - run anytime"""
    print("=" * 60)
    print("DEBUG INFO")
    print("=" * 60)
    print(f"Profile: {profile_uuid[:16]}... ({PROFILE_OS})")
    print(f"DevTools: http://localhost:{debug_port}")
    print(f"")
    print(f"Current Page:")
    print(f"  URL: {page.url}")
    print(f"  Title: {await page.title()}")
    print(f"")
    print(f"All Tabs ({len(context.pages)}):")
    for i, p in enumerate(context.pages):
        marker = " <-- ACTIVE" if p == page else ""
        print(f"  [{i}] {p.url[:60]}{marker}")
    
    screenshot_path = "/tmp/debug_cursor.png"
    await page.screenshot(path=screenshot_path)
    print(f"")
    print(f"Screenshot: {screenshot_path}")
    print("=" * 60)

def print_devtools_info():
    """Print DevTools access info"""
    print(f"\n--- DevTools Access ---")
    print(f"  UI:      http://localhost:{debug_port}")
    print(f"  JSON:    http://localhost:{debug_port}/json/list")
    print(f"  Chrome:  chrome://inspect -> Configure -> localhost:{debug_port}")

# Uncomment to run:
# await debug_page()
# print_devtools_info()


# %% [7] Navigate to cursor.com
await page.goto("https://cursor.com")
await page.wait_for_load_state("load")
print(f"✓ Loaded: {await page.title()}")
print(f"  URL: {page.url}")


# %% [8] Click Sign In -> Opens Auth Tab
initial_tabs = len(context.pages)
print(f"Tabs before: {initial_tabs}")

# Find and click sign in
sign_in = page.get_by_role("link", name="Sign in").or_(
    page.get_by_text("Sign in", exact=True)
)
await sign_in.wait_for(state="visible", timeout=10000)
await sign_in.evaluate("el => el.click()")  # JS click bypasses CDP latency

# Wait for new tab
for _ in range(20):
    await asyncio.sleep(0.5)
    if len(context.pages) > initial_tabs:
        break

# Switch to auth tab
if len(context.pages) > initial_tabs:
    page = context.pages[-1]
    print(f"✓ Switched to auth tab: {page.url}")
else:
    print(f"No new tab, staying on: {page.url}")

# Wait for page to render
try:
    await page.wait_for_load_state("load", timeout=10000)
except:
    pass
await asyncio.sleep(2)
print(f"✓ Auth page ready")


# %% [9] Enter Email & Continue
# Generate email (marks prefix as used)
email = generate_email()

# Wait for and fill email input
await page.wait_for_selector('input[name="email"]', state="visible", timeout=30000)
email_input = page.locator('input[name="email"]')
await email_input.click()
await asyncio.sleep(0.3)
await email_input.fill(email)

# Click Continue
await asyncio.sleep(0.5)
btn = page.locator('button[type="submit"]').or_(
    page.locator('button.ak-PrimaryButton')
).or_(
    page.get_by_role("button", name="Continue")
)
await btn.wait_for(state="visible", timeout=5000)
await btn.click()

print(f"✓ Email submitted: {email}")


# %% [10] Select "Email sign-in code" Option
await asyncio.sleep(2)

btn = page.get_by_text("Email sign-in code").or_(
    page.get_by_text("email code", exact=False)
)
await btn.wait_for(state="visible", timeout=30000)
await btn.click()
await asyncio.sleep(3)

print("✓ Selected email code option - check your inbox")


# %% [11] Poll & Fill Email OTP
# This polls until code arrives - run stop() from another cell to break
otp = poll_email_code(email)

if otp:
    await fill_otp(page, otp)
    print(f"✓ Filled OTP: {otp}")
else:
    print("Stopped - manually enter code:")
    print("  otp = '123456'")
    print("  await fill_otp(page, otp)")


# %% [12] Wait for Phone Page
await asyncio.sleep(8)
print(f"✓ Phone page loaded")
print(f"  URL: {page.url}")


# %% [13] Get Phone Number from HeroSMS
activation_id, phone, phone_local = get_phone_number()
print(f"\n✓ Got phone: +{phone}")
print(f"  Activation ID: {activation_id}")


# %% [14] Fill Phone Form
await asyncio.sleep(2)

phone_formatted = format_phone_uk(phone_local)
country_code = CONFIG["phone_country_code"]

print(f"Filling: +{country_code} {phone_formatted}")

await set_react_input(page, 'input[name="country_code"]', country_code)
await asyncio.sleep(0.5)
await set_react_input(page, 'input[name="local_number"]', phone_formatted)

print("✓ Phone form filled")


# %% [15] Click "Send verification code"
btn = page.get_by_text("Send verification code")
await btn.click()
print("✓ Verification code requested - waiting for SMS...")


# %% [16] Poll & Fill SMS Code
# This polls until SMS arrives - run stop() from another cell to break
sms_code = poll_sms_code(activation_id)

if sms_code:
    await asyncio.sleep(2)
    await fill_otp(page, sms_code, fallback='input[type="tel"]')
    complete_sms(activation_id)
    print(f"✓ Filled SMS code: {sms_code}")
else:
    print("Stopped - manually enter code:")
    print("  sms_code = '123456'")
    print("  await fill_otp(page, sms_code, fallback='input[type=\"tel\"]')")
    print("  complete_sms(activation_id)")


# %% [17] Onboarding: Click "Maybe Later"
await asyncio.sleep(2)
btn = page.get_by_text("Maybe Later")
await btn.click()
print("✓ Clicked Maybe Later")


# %% [18] Onboarding: Click "Skip for now"
await asyncio.sleep(2)
btn = page.get_by_text("Skip for now")
await btn.click()
print("✓ Clicked Skip for now")


# %% [19] Privacy Modal: Continue (1/2)
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("✓ Privacy modal 1/2")


# %% [20] Privacy Modal: Continue (2/2)
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("✓ Privacy modal 2/2")


# %% [21] Refresh Dashboard
await asyncio.sleep(2)
await page.reload()
await asyncio.sleep(3)
print("✓ Page refreshed")
print(f"  URL: {page.url}")


# %% [22] Click Free Trial -> Capture Stripe URL
initial_pages = len(context.pages)

btn = page.get_by_text("Free 7-day trial")
await btn.click()

stripe_url = None
for _ in range(30):
    await asyncio.sleep(0.3)
    
    # Check for new tab with Stripe
    if len(context.pages) > initial_pages:
        stripe_tab = context.pages[-1]
        stripe_url = stripe_tab.url
        if "stripe" in stripe_url or "checkout" in stripe_url:
            print(f"✓ Stripe URL (new tab): {stripe_url}")
            await stripe_tab.close()
            break
    
    # Check for redirect
    current_url = page.url
    if "stripe" in current_url or "checkout" in current_url:
        stripe_url = current_url
        print(f"✓ Stripe URL (redirect): {stripe_url}")
        break

if not stripe_url or "stripe" not in stripe_url:
    print(f"⚠ Warning: URL doesn't look like Stripe: {stripe_url or page.url}")


# %% [23] Extract Session Token
await page.goto("https://cursor.com/dashboard")
await asyncio.sleep(2)

cookies = await context.cookies()
session_token = None
for cookie in cookies:
    if cookie["name"] == "WorkosCursorSessionToken":
        session_token = cookie["value"]
        break

token_decoded = unquote(session_token) if session_token else None

print(f"✓ Session token extracted")
print(f"  Length: {len(token_decoded) if token_decoded else 0} chars")


# %% [24] Save Results
# Save to file
output_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else "."
output_file = os.path.join(output_dir, "session_tokens.txt")

with open(output_file, "a") as f:
    f.write(f"{email}\t+{phone}\t{stripe_url}\t{token_decoded}\n")

print(f"✓ Saved to {output_file}")

# Print results
print("\n" + "=" * 60)
print("RESULTS")
print("=" * 60)
print(f"Email:  {email}")
print(f"Phone:  +{phone}")
print(f"Stripe: {stripe_url}")
print(f"Token:  {token_decoded[:50]}..." if token_decoded and len(token_decoded) > 50 else f"Token:  {token_decoded}")
print("=" * 60)


# %% [25] Cleanup - Run when completely done
print("Cleaning up...")

if browser:
    await browser.close()
    print("  Browser connection closed")

if playwright:
    await playwright.stop()
    print("  Playwright stopped")

# Stop the OctoBrowser profile
if profile_uuid:
    stop_profile(profile_uuid)
    print(f"  Profile {profile_uuid[:8]}... stopped")

print("\n✓ Cleanup complete")


# %% [26] Emergency: Cancel SMS (if needed)
# Run this if something went wrong and you need to cancel the SMS activation
# to get a refund from HeroSMS

# cancel_sms(activation_id)


# %% [27] Emergency: Stop Polling
# Run this cell to stop any polling loop (email or SMS)
stop()


# %% [28] Test: PixelScan Fingerprint Check (Optional)
# Run this to verify the profile's fingerprint on PixelScan
# Android/Windows profiles should show "No masking detected"

print("Testing fingerprint on PixelScan...")
await page.goto("https://pixelscan.net/fingerprint-check", timeout=60000)
await asyncio.sleep(12)

# Extract result
text = await page.evaluate("() => document.body.innerText")
if "No masking detected" in text:
    print("✓ PASS: No masking detected!")
elif "Masking detected" in text:
    print("✗ FAIL: Masking detected (antidetect browser fingerprint)")
else:
    print("? Unknown result - check manually")

# Key detection results
for line in text.split('\n'):
    if any(x in line for x in ['Proxy', 'Masking', 'Bot check', 'Fingerprint']):
        if 'detected' in line.lower() or 'pass' in line.lower() or 'no ' in line.lower():
            print(f"  {line.strip()}")

await debug_page()
