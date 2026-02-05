# %% [markdown]
# # Cursor Account Automation (OctoBrowser + Playwright)
# Automated Cursor account creation using OctoBrowser profiles with Playwright
# Migrated from zendriver version
#
# NOTE: This script uses async Playwright API with top-level `await` statements.
# This is valid in Jupyter/IPython notebooks. The linter errors about "await
# allowed only within async function" can be ignored - the notebook runtime
# automatically handles top-level await.

# %% [1] Imports & Config
import os
import sys
import asyncio
import random
import subprocess
import time as _time
import requests
from urllib.parse import unquote
from playwright.async_api import async_playwright, Page, Browser

# Add herosms to path (shared under /allah/blue/web/auto/)
sys.path.insert(0, "/allah/blue/web/auto/herosms")
import herosms

# OctoBrowser paths and config
OCTO_APPIMAGE = "/home/vncuser/Downloads/OctoBrowser.AppImage"
OCTO_PORT_FILE = os.path.expanduser("~/.Octo Browser/local_port")
OCTO_DEFAULT_PORT = "56933"

# Read port or use default
OCTO_PORT = None
try:
    with open(OCTO_PORT_FILE) as f:
        OCTO_PORT = f.read().strip()
except FileNotFoundError:
    OCTO_PORT = OCTO_DEFAULT_PORT
OCTO_API = f"http://localhost:{OCTO_PORT}"


def is_octo_running():
    """Check if OctoBrowser API is available"""
    try:
        resp = requests.get(f"{OCTO_API}/api/v2/client/themes", timeout=3)
        return resp.status_code == 200 and resp.json().get("success")
    except:
        return False


def start_octo_browser():
    """Start OctoBrowser if not already running"""
    global OCTO_PORT, OCTO_API
    
    if is_octo_running():
        print(f"OctoBrowser already running at {OCTO_API}")
        return True
    
    print("OctoBrowser not running. Starting...")
    
    if not os.path.exists(OCTO_APPIMAGE):
        print(f"ERROR: OctoBrowser not found at {OCTO_APPIMAGE}")
        return False
    
    # Environment for running as root with sandbox disabled
    env = os.environ.copy()
    env["DISPLAY"] = ":1"
    env["OCTO_EXTRA_ARGS"] = "--no-sandbox"
    env["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu-sandbox"
    
    # Start OctoBrowser in background
    subprocess.Popen(
        [OCTO_APPIMAGE, "--no-sandbox"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    
    # Wait for API to become available
    print("Waiting for OctoBrowser API...")
    for i in range(60):  # Wait up to 60 seconds
        _time.sleep(1)
        
        # Re-read port in case it changed
        try:
            with open(OCTO_PORT_FILE) as f:
                OCTO_PORT = f.read().strip()
                OCTO_API = f"http://localhost:{OCTO_PORT}"
        except FileNotFoundError:
            pass
        
        if is_octo_running():
            print(f"OctoBrowser started! API: {OCTO_API}")
            return True
        
        if i % 10 == 9:
            print(f"  Still waiting... ({i+1}s)")
    
    print("ERROR: OctoBrowser failed to start within 60 seconds")
    return False


# Settings (edit these as needed)
CONFIG = {
    "profile_uuid": None,  # Will be set when profile is created/selected
    "email_domain": "@hyas.site",
    "prefixes_file": "/allah/blue/web/auto/worker/hyas_prefixes.txt",
    "email_worker_url": "https://cursor-email-worker.jar711red.workers.dev",
    "phone_country_id": 16,       # UK
    "phone_country_code": "44",
    "phone_service": "ot",
}

# Module-level state (persists across cells)
playwright = None
browser = None
context = None
page = None
profile_uuid = None
email = None
phone = None
phone_local = None
phone_formatted = None
activation_id = None
stripe_url = None
session_token = None

# Start OctoBrowser if needed
if not start_octo_browser():
    raise RuntimeError("OctoBrowser is required but could not be started")

print(f"Imports loaded. Octo API: {OCTO_API}")


# %% [2] Octo Browser Helper Functions
def octo_list_profiles():
    """List all OctoBrowser profiles"""
    resp = requests.post(f"{OCTO_API}/api/v2/profiles/list", json={})
    data = resp.json()
    if data.get("success"):
        return data["data"]["profiles"]
    raise Exception(f"Failed to list profiles: {data}")


def octo_create_profile(title="Cursor Automation", os_type="win"):
    """Create a new OctoBrowser profile with random fingerprint"""
    resp = requests.post(
        f"{OCTO_API}/api/v2/profiles/quick",
        json={"title": title, "os": os_type}
    )
    data = resp.json()
    if data.get("success"):
        print(f"Created profile: {data['data']['title']} ({data['data']['uuid']})")
        return data["data"]["uuid"]
    raise Exception(f"Failed to create profile: {data}")


def octo_start_profile(uuid):
    """Start OctoBrowser profile and return ws_endpoint"""
    import time
    # Stop if already running
    requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": uuid})
    time.sleep(2)
    
    # Start profile using OLD API with debug_port=True to get ws_endpoint
    resp = requests.post(
        f"{OCTO_API}/api/profiles/start",
        json={"uuid": uuid, "debug_port": True}
    )
    data = resp.json()
    
    ws_endpoint = data.get("ws_endpoint")
    if ws_endpoint:
        return ws_endpoint
    
    # Fallback: check alternative field names
    ws_endpoint = data.get("wsEndpoint") or data.get("data", {}).get("ws_endpoint")
    if ws_endpoint:
        return ws_endpoint
    
    raise Exception(f"Failed to get ws_endpoint: {data}")


def octo_stop_profile(uuid):
    """Stop OctoBrowser profile"""
    requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": uuid})
    print(f"Profile {uuid} stopped")


def octo_get_profile_view(uuid):
    """Get profile view/status"""
    resp = requests.get(f"{OCTO_API}/api/v2/profiles/{uuid}/view")
    data = resp.json()
    if data.get("success"):
        return data["data"]
    return {}


print("Octo helpers loaded")


# %% [3] Cursor Automation Helper Functions
def generate_email():
    """Generate email using random available prefix from file, mark as used."""
    prefixes_file = CONFIG["prefixes_file"]
    
    with open(prefixes_file, "r") as f:
        lines = f.readlines()
    
    available = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "# USED" not in line:
            available.append((i, stripped))
    
    if not available:
        raise RuntimeError("No available prefixes in " + prefixes_file)
    
    idx, prefix = random.choice(available)
    lines[idx] = f"{prefix} # USED\n"
    with open(prefixes_file, "w") as f:
        f.writelines(lines)
    
    return f"{prefix}{CONFIG['email_domain']}"


# Smart stop mechanism - run stop() from another cell to break polling
class StopSignal:
    _stop = False
    
    @classmethod
    def stop(cls):
        """Call this to stop polling"""
        cls._stop = True
        print("Stop signal sent - polling will stop on next iteration")
    
    @classmethod
    def reset(cls):
        """Reset the stop signal"""
        cls._stop = False
    
    @classmethod
    def check(cls):
        """Check and reset if stopped"""
        if cls._stop:
            cls._stop = False
            return True
        return False

# Convenience function
def stop():
    """Stop any running poll - call from another cell"""
    StopSignal.stop()


def poll_email_code(email_addr: str, timeout: int = 300, interval: int = 5) -> str:
    """Poll worker for email OTP code. Call stop() from another cell to break."""
    import time
    print(f"Polling for email code: {email_addr}")
    print("  (Run `stop()` in another cell to break out)")
    url = CONFIG["email_worker_url"]
    StopSignal.reset()
    
    for i in range(timeout // interval):
        if StopSignal.check():
            print("Stopped by user")
            return None
        
        try:
            resp = requests.get(
                f"{url}/code",
                params={"email": email_addr, "service": "cursor"},
                timeout=10
            )
            if resp.status_code == 200:
                code = resp.json().get("code")
                print(f"EMAIL CODE: {code}")
                return code
            elif resp.status_code == 404:
                print(f"[{i * interval:3d}s] waiting...")
        except Exception as e:
            print(f"[{i * interval:3d}s] error: {e}")
        time.sleep(interval)
    
    raise TimeoutError(f"No code in {timeout}s")


def poll_sms_code(act_id: str, timeout: int = 300, interval: int = 5) -> str:
    """Poll HeroSMS for SMS code. Call stop() from another cell to break."""
    import time
    print("Polling for SMS code...")
    print("  (Run `stop()` in another cell to break out)")
    StopSignal.reset()
    
    for i in range(timeout // interval):
        if StopSignal.check():
            print("Stopped by user")
            return None
        
        status = herosms.get_status(act_id)
        print(f"[{i * interval:3d}s] {status}")
        
        if status.startswith("STATUS_OK:"):
            code = status.split(":")[1]
            print(f"SMS CODE: {code}")
            return code
        elif status == "STATUS_CANCEL":
            raise Exception("Cancelled")
        time.sleep(interval)
    
    herosms.cancel(act_id)
    raise TimeoutError(f"No code in {timeout}s")


async def fill_otp(page: Page, code: str, fallback: str = None):
    """Fill OTP inputs digit by digit."""
    for i, digit in enumerate(str(code)):
        try:
            inp = page.locator(f'input[data-index="{i}"]')
            if await inp.count() > 0:
                await inp.fill(digit)
                await asyncio.sleep(0.2)
            else:
                raise Exception("Input not found")
        except:
            if fallback:
                inp = page.locator(fallback)
                if await inp.count() > 0:
                    await inp.fill(code)
                    return
            raise


async def set_react_input(page: Page, selector: str, value: str):
    """Set React controlled input value with human-like typing."""
    await page.evaluate(f'''
        (async function() {{
            const input = document.querySelector('{selector}');
            if (!input) return;
            input.focus();
            
            const nativeSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            ).set;
            
            input.select();
            await new Promise(r => setTimeout(r, 50));
            
            nativeSetter.call(input, '');
            input.dispatchEvent(new Event('input', {{ bubbles: true }}));
            await new Promise(r => setTimeout(r, 50));
            
            for (let char of '{value}') {{
                const currentValue = input.value;
                nativeSetter.call(input, currentValue + char);
                input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                await new Promise(r => setTimeout(r, 80));
            }}
            
            input.dispatchEvent(new Event('change', {{ bubbles: true }}));
            input.blur();
        }})();
    ''')
    await asyncio.sleep(len(value) * 0.1 + 0.3)


print("Cursor helpers loaded")


# %% [3.5] DELETE ALL PROFILES (uncomment to run - DANGEROUS!)
# # WARNING: This will delete ALL OctoBrowser profiles permanently!
# def octo_delete_all_profiles():
#     """Delete all OctoBrowser profiles"""
#     profiles = octo_list_profiles()
#     if not profiles:
#         print("No profiles to delete")
#         return
#     
#     print(f"Deleting {len(profiles)} profiles...")
#     uuids = [p["uuid"] for p in profiles]
#     
#     # Stop all running profiles first
#     for uuid in uuids:
#         requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": uuid})
#     
#     import time
#     time.sleep(2)
#     
#     # Delete all profiles
#     resp = requests.post(
#         f"{OCTO_API}/api/v2/profiles/delete",
#         json={"uuids": uuids}
#     )
#     data = resp.json()
#     if data.get("success"):
#         print(f"Deleted {len(uuids)} profiles")
#     else:
#         print(f"Delete failed: {data}")
#
# octo_delete_all_profiles()


# %% [4] Create/Select Profile
import time as _time

profiles = octo_list_profiles()
print(f"Found {len(profiles)} profiles:")
for p in profiles:
    status = "running" if p.get("status") == 6 else "stopped"
    print(f"  - {p['title']} ({p['uuid'][:8]}...) [{status}]")

# Create new profile with macOS fingerprint
profile_uuid = octo_create_profile(f"Cursor-{int(_time.time())}", os_type="mac")
CONFIG["profile_uuid"] = profile_uuid


# %% [5] Start Browser & Connect Playwright
import time as _time

print(f"Starting profile: {profile_uuid}")

# Stop profile first (in case it's already running)
requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": profile_uuid})
_time.sleep(2)

# Start profile using OLD API with debug_port=True to get ws_endpoint
resp = requests.post(
    f"{OCTO_API}/api/profiles/start",
    json={"uuid": profile_uuid, "debug_port": True}
)
data = resp.json()
print(f"Start response: {data}")

ws_endpoint = data.get("ws_endpoint")

if not ws_endpoint:
    print("WARNING: No WebSocket endpoint in response.")
    print(f"Full response: {data}")
    
    # Fallback: check if there's a different field name
    ws_endpoint = data.get("wsEndpoint") or data.get("data", {}).get("ws_endpoint")
    
if ws_endpoint:
    print(f"WebSocket endpoint: {ws_endpoint}")
else:
    print("ERROR: Could not get WebSocket endpoint. Check OctoBrowser is running.")


# %% [6] Connect Playwright (async)
playwright = await async_playwright().start()

if ws_endpoint:
    browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
    context = browser.contexts[0]
    
    if context.pages:
        page = context.pages[0]
    else:
        page = await context.new_page()
    
    print(f"Connected! Pages: {len(context.pages)}")
else:
    raise Exception("No WebSocket endpoint - cannot connect")


# %% [6.5] Debug Helper (run anytime to check page state)
async def debug_page():
    """Take screenshot and print current state"""
    print(f"URL: {page.url}")
    print(f"Title: {await page.title()}")
    print(f"Pages in context: {len(context.pages)}")
    screenshot_path = "/tmp/debug_cursor.png"
    await page.screenshot(path=screenshot_path)
    print(f"Screenshot: {screenshot_path}")

# Uncomment to run debug:
# await debug_page()


# %% [7] Navigate to Cursor
await page.goto("https://cursor.com")
await page.wait_for_load_state("load")
print(f"Page loaded: {await page.title()}")
print(f"URL: {page.url}")


# %% [8] Click Sign In -> New Tab
# Remember initial tab count
initial_tabs = len(context.pages)
print(f"Initial tabs: {initial_tabs}")

# Wait for sign in button to be visible
sign_in = page.get_by_role("link", name="Sign in").or_(page.get_by_text("Sign in", exact=True))
await sign_in.wait_for(state="visible", timeout=10000)
await sign_in.click()

# Wait for new tab to open (poll for up to 10 seconds)
for _ in range(20):
    await asyncio.sleep(0.5)
    if len(context.pages) > initial_tabs:
        break

# Switch to the new tab (auth page)
print(f"Tabs after click: {len(context.pages)}")
if len(context.pages) > initial_tabs:
    page = context.pages[-1]
    print(f"Switched to new tab: {page.url}")
else:
    print(f"No new tab, staying on: {page.url}")

# Wait for the auth page to load (use "load" instead of "networkidle" - OctoBrowser has background requests)
try:
    await page.wait_for_load_state("load", timeout=10000)
except:
    pass  # Continue anyway
await asyncio.sleep(2)  # Extra wait for React to render
print(f"Sign in page ready: {page.url}")


# %% [9] Enter Email & Continue
# Debug: show which page we're on
print(f"Current page URL: {page.url}")
print(f"Total tabs: {len(context.pages)}")
for i, p in enumerate(context.pages):
    print(f"  Tab {i}: {p.url}")

email = generate_email()

# Wait for page to be ready
await page.wait_for_selector('input[name="email"]', state="visible", timeout=30000)

# Fill email using the most specific selector
email_input = page.locator('input[name="email"]')
await email_input.click()
await asyncio.sleep(0.3)
await email_input.fill(email)
print(f"Email: {email}")

# Find and click Continue button (it's a submit button)
await asyncio.sleep(0.5)
btn = page.locator('button[type="submit"]').or_(
    page.locator('button.ak-PrimaryButton')
).or_(
    page.get_by_role("button", name="Continue")
)
await btn.wait_for(state="visible", timeout=5000)
await btn.click()
print("Clicked Continue")


# %% [10] Select Email Code Option
# Wait for auth options to appear (use element wait instead of networkidle)
await asyncio.sleep(2)
btn = page.get_by_text("Email sign-in code").or_(page.get_by_text("email code", exact=False))
await btn.wait_for(state="visible", timeout=30000)
await btn.click()
await asyncio.sleep(3)
print("Selected email code option")


# %% [11] Get & Fill Email OTP
otp = poll_email_code(email)
if otp:
    await fill_otp(page, otp)
    print(f"Filled OTP: {otp}")
else:
    print("Stopped - enter code manually: otp = '123456'; await fill_otp(page, otp)")


# %% [12] Wait for Phone Page
await asyncio.sleep(8)
print("Phone page loaded")


# %% [13] Get Phone from HeroSMS
phone_country_id = CONFIG["phone_country_id"]
phone_country_code = CONFIG["phone_country_code"]
phone_service = CONFIG["phone_service"]

print(f"HeroSMS Balance: ${herosms.get_balance()}")
activation_id, phone = herosms.get_number(
    service=phone_service,
    country=phone_country_id
)
phone_local = phone[len(phone_country_code):] if phone.startswith(phone_country_code) else phone
print(f"Phone: +{phone} -> local: {phone_local}")
herosms.mark_ready(activation_id)


# %% [14] Fill Phone Form
await asyncio.sleep(2)

phone_formatted = f"({phone_local[:3]}){phone_local[3:6]}-{phone_local[6:]}" if len(phone_local) >= 10 else phone_local
print(f"Formatted: {phone_formatted}")

await set_react_input(page, 'input[name="country_code"]', phone_country_code)
print(f"Country code: {phone_country_code}")
await asyncio.sleep(0.5)

await set_react_input(page, 'input[name="local_number"]', phone_formatted)
print(f"Local number: {phone_formatted}")
await asyncio.sleep(0.5)

print("Phone form filled")


# %% [15] Send Verification Code
btn = page.get_by_text("Send verification code")
await btn.click()
print("Verification code requested")


# %% [16] Get & Fill SMS Code
sms_code = poll_sms_code(activation_id)
if sms_code:
    await asyncio.sleep(2)
    await fill_otp(page, sms_code, fallback='input[type="tel"]')
    print(f"Filled SMS: {sms_code}")
    herosms.complete(activation_id)
    print("HeroSMS completed")
else:
    print("Stopped - enter code manually: sms_code = '123456'; await fill_otp(page, sms_code, fallback='input[type=\"tel\"]'); herosms.complete(activation_id)")


# %% [17] Onboarding: Maybe Later
await asyncio.sleep(2)
btn = page.get_by_text("Maybe Later")
await btn.click()
print("Clicked Maybe Later")


# %% [18] Onboarding: Skip for now
await asyncio.sleep(2)
btn = page.get_by_text("Skip for now")
await btn.click()
print("Clicked Skip for now")


# %% [19] Privacy: Continue (first)
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("Privacy modal 1")


# %% [20] Privacy: Continue (second)
await asyncio.sleep(2)
btn = page.get_by_text("Continue")
await btn.click()
print("Privacy modal 2")


# %% [21] Refresh Page
await asyncio.sleep(2)
await page.reload()
await asyncio.sleep(3)
print("Page refreshed")


# %% [22] Click Free Trial -> Get Stripe URL -> Back to Dashboard
initial_pages = len(context.pages)
btn = page.get_by_text("Free 7-day trial")
await btn.click()

stripe_url = None
for _ in range(30):
    await asyncio.sleep(0.3)
    
    if len(context.pages) > initial_pages:
        stripe_tab = context.pages[-1]
        stripe_url = stripe_tab.url
        if "stripe" in stripe_url or "checkout" in stripe_url:
            print(f"Stripe URL (new tab): {stripe_url}")
            await stripe_tab.close()
            break
    
    current_url = page.url
    if "stripe" in current_url or "checkout" in current_url:
        stripe_url = current_url
        print(f"Stripe URL (redirect): {stripe_url}")
        break

if not stripe_url or "stripe" not in stripe_url:
    print(f"Warning: Not Stripe? URL: {stripe_url or page.url}")

await page.goto("https://cursor.com/dashboard")
await asyncio.sleep(2)

cookies = await context.cookies()
session_token = None
for cookie in cookies:
    if cookie["name"] == "WorkosCursorSessionToken":
        session_token = cookie["value"]
        break

token_decoded = unquote(session_token) if session_token else None

output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else ".", "session_tokens.txt")
with open(output_file, "a") as f:
    f.write(f"{email}\t+{phone}\t{stripe_url}\t{token_decoded}\n")
print(f"Saved to {output_file}")

print("\n" + "=" * 60)
print("RESULTS (each value on own line for easy copy)")
print("=" * 60)
print("Email:")
print(email)
print("\nPhone:")
print(f"+{phone}")
print("\nStripe:")
print(stripe_url)
print("\nToken:")
print(token_decoded)
print("=" * 60)


# %% [23] Cleanup (run when done)
if browser:
    await browser.close()
if playwright:
    await playwright.stop()
print("Playwright disconnected")

# Optionally stop the profile (uncomment to close browser)
# octo_stop_profile(profile_uuid)
# print("Profile stopped")

# %%
