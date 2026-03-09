# %% [markdown]
# # Cursor Account Automation
# 
# Run cells sequentially to create a Cursor account.
# Uses cli.py for all OctoBrowser operations.
#
# **Usage:**
# - Run cells in order (Shift+Enter)
# - Use `stop()` to break polling loops
# - Run `await debug_page()` to check state

# %% [1] Initialize
import os
import time
import asyncio
from urllib.parse import unquote
from playwright.async_api import async_playwright

from api_cli import get_api, api_get, api_post, parse_proxy_url
from config import CONFIG, verify_paths
from cursor_helpers import (
    stop, generate_email, count_available_prefixes,
    poll_email_code, poll_sms_code,
    get_phone_number, format_phone_uk, complete_sms, cancel_sms,
    fill_otp, set_react_input
)

# Verify environment
print("Verifying paths...")
if not verify_paths():
    raise RuntimeError("Missing required files")

# Check OctoBrowser
resp = api_get("/api/v2/client/themes", timeout=3)
if resp.get("error"):
    raise RuntimeError(f"OctoBrowser not running: {resp['error']}")

print(f"✓ OctoBrowser API: {get_api()}")
count_available_prefixes()


# %% [2] Session State
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

# Configuration
PROFILE_OS = "android"  # android, win, mac
PROXY_URL = "https://user-sp19qgy7m9-country-de-session-32c2d04dcd49-sessionduration-60:+26iSboeQ0wUyx4qEw@de.decodo.com:48999"

print(f"Profile: {PROFILE_OS}")
print(f"Proxy: {PROXY_URL.split('@')[1] if '@' in PROXY_URL else PROXY_URL}")


# %% [3] Create Profile
os_arch = "arm" if PROFILE_OS in ["mac", "android"] else "x86"

# Get boilerplate
resp = api_post(
    "/api/v2/profiles/boilerplate/quick",
    {"os": PROFILE_OS, "os_arch": os_arch, "count": 1}
)
if not resp.get("success"):
    raise RuntimeError(f"Boilerplate failed: {resp}")

bp = resp["data"]["boilerplates"][0]
fp = bp["fp"]

print(f"\nFingerprint:")
print(f"  OS: {fp.get('os')} v{fp.get('os_version')}")
if PROFILE_OS == "android":
    print(f"  Device: {fp.get('device_model')}")
print(f"  GPU: {fp.get('renderer')}")

# Fix dns
if fp.get("dns") is None:
    fp["dns"] = ""

# Enable noise
fp["noise"] = {"webgl": True, "canvas": True, "audio": True, "client_rects": True}
fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}
print(f"  Noise: ✓")

# Storage options
storage_opts = bp.get("storage_options", {})
if PROFILE_OS == "android":
    storage_opts["extensions"] = False

# Proxy
proxy_config = parse_proxy_url(PROXY_URL) if PROXY_URL else {"type": "direct"}
if proxy_config and proxy_config.get("data"):
    pd = proxy_config["data"]
    print(f"  Proxy: {pd['ip']}:{pd['port']}")

# Create
title = f"Cursor-{PROFILE_OS.title()}-{int(time.time())}"
payload = {
    "title": title,
    "name": title,
    "description": "",
    "start_pages": [],
    "bookmarks": [],
    "launch_args": [],
    "logo": bp.get("logo", ""),
    "tags": [],
    "fp": fp,
    "proxy": proxy_config,
    "proxies": [],
    "local_cache": False,
    "storage_options": storage_opts,
    "extensions": [],
}

resp = api_post("/api/v2/profiles", payload)
if not resp.get("success"):
    raise RuntimeError(f"Create failed: {resp}")

profile_uuid = resp["data"]["uuid"]
print(f"\n✓ Created: {title}")
print(f"  UUID: {profile_uuid}")


# %% [4] Start Profile
print(f"Starting: {profile_uuid[:16]}...")

api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
time.sleep(2)

resp = api_post(
    "/api/profiles/start",
    {"uuid": profile_uuid, "debug_port": True},
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


# %% [7] Navigate to cursor.com
await page.goto("https://cursor.com")
await page.wait_for_load_state("load")
print(f"✓ Loaded: {await page.title()}")


# %% [8] Click Sign In
initial_tabs = len(context.pages)

sign_in = page.get_by_role("link", name="Sign in").or_(
    page.get_by_text("Sign in", exact=True)
)
await sign_in.wait_for(state="visible", timeout=10000)
await sign_in.evaluate("el => el.click()")

for _ in range(20):
    await asyncio.sleep(0.5)
    if len(context.pages) > initial_tabs:
        break

if len(context.pages) > initial_tabs:
    page = context.pages[-1]
    print(f"✓ Auth tab: {page.url}")

await asyncio.sleep(2)


# %% [9] Enter Email
email = generate_email()

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


# %% [11] Fill Email OTP
otp = poll_email_code(email)

if otp:
    await fill_otp(page, otp)
    print(f"✓ OTP: {otp}")
else:
    print("Stopped. Manual: otp = '123456'; await fill_otp(page, otp)")


# %% [12] Wait for Phone Page
await asyncio.sleep(8)
print(f"✓ Phone page: {page.url}")


# %% [13] Get Phone Number
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


# %% [15] Send SMS
btn = page.get_by_text("Send verification code")
await btn.click()
print("✓ SMS requested")


# %% [16] Fill SMS Code
sms_code = poll_sms_code(activation_id)

if sms_code:
    await asyncio.sleep(2)
    await fill_otp(page, sms_code, fallback='input[type="tel"]')
    complete_sms(activation_id)
    print(f"✓ SMS: {sms_code}")
else:
    print("Stopped. Manual: complete_sms(activation_id)")


# %% [17] Maybe Later
await asyncio.sleep(2)
btn = page.get_by_text("Maybe Later")
await btn.click()
print("✓ Maybe Later")


# %% [18] Skip for now
await asyncio.sleep(2)
btn = page.get_by_text("Skip for now")
await btn.click()
print("✓ Skip")


# %% [19] Continue 1/2
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("✓ Continue 1/2")


# %% [20] Continue 2/2
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("✓ Continue 2/2")


# %% [21] Refresh
await asyncio.sleep(2)
await page.reload()
await asyncio.sleep(3)
print(f"✓ Refreshed: {page.url}")


# %% [22] Get Stripe URL
initial_pages = len(context.pages)

btn = page.get_by_text("Free 7-day trial")
await btn.click()

stripe_url = None
for _ in range(30):
    await asyncio.sleep(0.3)
    
    if len(context.pages) > initial_pages:
        stripe_tab = context.pages[-1]
        stripe_url = stripe_tab.url
        if "stripe" in stripe_url:
            print(f"✓ Stripe: {stripe_url}")
            await stripe_tab.close()
            break
    
    if "stripe" in page.url:
        stripe_url = page.url
        print(f"✓ Stripe: {stripe_url}")
        break


# %% [23] Extract Token
await page.goto("https://cursor.com/dashboard")
await asyncio.sleep(2)

cookies = await context.cookies()
session_token = None
for cookie in cookies:
    if cookie["name"] == "WorkosCursorSessionToken":
        session_token = cookie["value"]
        break

token_decoded = unquote(session_token) if session_token else None
print(f"✓ Token: {len(token_decoded) if token_decoded else 0} chars")


# %% [24] Save Results
output_file = os.path.join(os.path.dirname(__file__), "..", "docs", "octo_session_tokens.txt")

with open(output_file, "a") as f:
    f.write(f"{email}\t+{phone}\t{stripe_url}\t{token_decoded}\n")

print(f"\n{'='*50}")
print("RESULTS")
print("=" * 50)
print(f"Email:  {email}")
print(f"Phone:  +{phone}")
print(f"Stripe: {stripe_url}")
print(f"Token:  {token_decoded[:50]}..." if token_decoded else "Token: None")
print("=" * 50)


# %% [25] Cleanup
print("Cleaning up...")

if browser:
    await browser.close()

if playwright:
    await playwright.stop()

if profile_uuid:
    api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
    print(f"  Profile stopped")

print("✓ Done")


# %% [26] Emergency: Cancel SMS
# cancel_sms(activation_id)


# %% [27] Emergency: Stop Polling
stop()


# %% [28] Test PixelScan
print("Testing PixelScan...")
await page.goto("https://pixelscan.net/fingerprint-check", timeout=60000)
await asyncio.sleep(12)

text = await page.evaluate("() => document.body.innerText")
if "No masking detected" in text:
    print("✓ PASS: No masking")
elif "Masking detected" in text:
    print("✗ FAIL: Masking detected")

await debug_page()
