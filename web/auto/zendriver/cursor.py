# %% [1] Imports & Config
import os
import sys
import time
import random
import string
import requests
import zendriver as zd

sys.path.insert(0, "/allah/blue/web/auto/zendriver/herosms")
import herosms

# Display config - copy Xauthority for root access
import shutil
shutil.copy("/home/vncuser/.Xauthority", "/root/.Xauthority")
os.environ["DISPLAY"] = ":1"
os.environ["XAUTHORITY"] = "/root/.Xauthority"

# Settings (edit these as needed)
CONFIG = {
    "profile_dir": "/tmp/cursor_chrome_profile",
    "email_domain": "@hyas.site",
    "email_worker_url": "https://cursor-email-worker.jar711red.workers.dev",
    "phone_country_id": 62,      # Turkey
    "phone_country_code": "90",
    "phone_service": "ot",
    "phone_fixed_price": 0.05,
}

# Module-level state (persists across cells)
browser = None
page = None
email = None
phone = None
phone_local = None
phone_formatted = None
activation_id = None
stripe_url = None
session_token = None

print("Imports loaded")


# %% [2] Helper Functions
def generate_email():
    """Generate random email."""
    prefix = ''.join(random.choices(string.ascii_lowercase, k=5))
    return f"{prefix}{CONFIG['email_domain']}"


def format_phone(phone_number: str) -> tuple[str, str]:
    """Parse phone to (local, formatted). Returns (9171234567, (917)123-4567)."""
    cc = CONFIG["phone_country_code"]
    local = phone_number[len(cc):] if phone_number.startswith(cc) else phone_number
    # formatted = f"({local[:3]}){local[3:6]}-{local[6:]}"
    return local, local  # Use raw local number without formatting


def poll_email_code(email_addr: str, timeout: int = 300, interval: int = 5) -> str:
    """Poll worker for email OTP code."""
    print(f"Polling for email code: {email_addr}")
    url = CONFIG["email_worker_url"]
    
    for i in range(timeout // interval):
        try:
            resp = requests.get(f"{url}/code", params={"email": email_addr, "service": "cursor"}, timeout=10)
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
    """Poll HeroSMS for SMS code."""
    print("Polling for SMS code...")
    
    for i in range(timeout // interval):
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


async def fill_otp(code: str, fallback: str = None):
    """Fill OTP inputs digit by digit."""
    for i, digit in enumerate(str(code)):
        try:
            inp = await page.select(f'input[data-index="{i}"]')
            await inp.send_keys(digit)
            await page.sleep(0.2)
        except:
            if fallback:
                inp = await page.select(fallback)
                await inp.send_keys(code)
                return
            raise


async def set_react_input(selector: str, value: str):
    """Set React controlled input value with human-like typing."""
    await page.evaluate(f'''
        (async function() {{
            const input = document.querySelector('{selector}');
            input.focus();
            
            const nativeSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            ).set;
            
            // Select all
            input.select();
            await new Promise(r => setTimeout(r, 50));
            
            // Clear
            nativeSetter.call(input, '');
            input.dispatchEvent(new Event('input', {{ bubbles: true }}));
            await new Promise(r => setTimeout(r, 50));
            
            // Type character by character
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

print("Helpers loaded")


# %% [3] Launch Browser
browser = await zd.start(
    headless=False,
    sandbox=False,  # Required when running as root
    user_data_dir=CONFIG["profile_dir"],
    browser_args=[
        "--disable-dev-shm-usage",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer", 
        "--disable-gpu-compositing",
        "--remote-debugging-port=0",  # Let Chrome pick an available port
    ],
)
page = await browser.get("https://cursor.com")
await page.sleep(5)
print(f"Browser ready: {CONFIG['profile_dir']}")


# %% [4] Click Sign In -> New Tab
sign_in = await page.find("Sign in")
await sign_in.click()
await page.sleep(3)
page = browser.tabs[-1]
await page.sleep(3)
print(f"Sign in page: {page.target.url}")


# %% [5] Enter Email & Continue
email = generate_email()
email_input = await page.select('input[type="email"]')
await email_input.send_keys(email)
print(f"Email: {email}")

btn = await page.find("Continue")
await btn.click()
print("Clicked Continue")


# %% [6] Select Email Code Option
await page.sleep(5)
btn = await page.find("Email sign-in code")
await btn.click()
await page.sleep(3)
print("Selected email code option")


# %% [7] Get & Fill Email OTP
otp = poll_email_code(email)
await fill_otp(otp)
print(f"Filled OTP: {otp}")


# %% [8] Wait for Phone Page
await page.sleep(8)
print("Phone page loaded")


# %% [9] Get Phone from HeroSMS
# Debug: redefine here for easy editing
phone_country_id = 6        # Indonesia
phone_country_code = "62"
phone_service = "ot"

print(f"HeroSMS Balance: ${herosms.get_balance()}")
activation_id, phone = herosms.get_number(
    service=phone_service,
    country=phone_country_id
)
phone_local = phone[len(phone_country_code):] if phone.startswith(phone_country_code) else phone
print(f"Phone: +{phone} -> local: {phone_local}")
herosms.mark_ready(activation_id)


# %% [10] Fill Phone Form (Debug: re-run this cell if it fails)
await page.sleep(2)

# Format: (xxx)xxx-xxxx
phone_formatted = f"({phone_local[:3]}){phone_local[3:6]}-{phone_local[6:]}"
print(f"Formatted: {phone_formatted}")

# Set country code
await set_react_input('input[name="country_code"]', phone_country_code)
print(f"Country code: {phone_country_code}")
await page.sleep(0.5)

# Set local number
await set_react_input('input[name="local_number"]', phone_formatted)
print(f"Local number: {phone_formatted}")
await page.sleep(0.5)

print("Phone form filled")


# %% [11] Send Verification Code
btn = await page.find("Send verification code")
await btn.click()
print("Verification code requested")


# %% [12] Get & Fill SMS Code
sms_code = poll_sms_code(activation_id)
await page.sleep(2)
await fill_otp(sms_code, fallback='input[type="tel"]')
print(f"Filled SMS: {sms_code}")

herosms.complete(activation_id)
print("HeroSMS completed")


# %% [13] Onboarding: Maybe Later
await page.sleep(2)
btn = await page.find("Maybe Later")
await btn.click()
print("Clicked Maybe Later")


# %% [14] Onboarding: Skip for now
await page.sleep(2)
btn = await page.find("Skip for now")
await btn.click()
print("Clicked Skip for now")


# %% [15] Privacy: Continue (first)
await page.sleep(2)
btn = await page.find("Continue")
await btn.click()
print("Privacy modal 1")


# %% [16] Privacy: Continue (second)
await page.sleep(2)
btn = await page.find("Continue")
await btn.click()
print("Privacy modal 2")


# %% [17] Refresh Page
await page.sleep(2)
await page.reload()
await page.sleep(3)
print("Page refreshed")


# %% [18] Click Free Trial -> Get Stripe URL -> Back to Dashboard
initial_tabs = len(browser.tabs)
btn = await page.find("Free 7-day trial")
await btn.click()

# Wait for Stripe - could be new tab or redirect
stripe_url = None
for _ in range(30):
    await page.sleep(0.3)
    
    # Check if new tab opened (Stripe checkout often opens in new tab)
    if len(browser.tabs) > initial_tabs:
        stripe_tab = browser.tabs[-1]
        stripe_url = stripe_tab.target.url
        if "stripe" in stripe_url or "checkout" in stripe_url:
            print(f"Stripe URL (new tab): {stripe_url}")
            await stripe_tab.close()
            break
    
    # Also check current page redirect
    current_url = page.target.url
    if "stripe" in current_url or "checkout" in current_url:
        stripe_url = current_url
        print(f"Stripe URL (redirect): {stripe_url}")
        break

if not stripe_url or "stripe" not in stripe_url:
    print(f"Warning: Not Stripe? URL: {stripe_url or page.target.url}")

# Immediately go back to dashboard
await page.get("https://cursor.com/dashboard")
await page.sleep(2)

cookies = await browser.cookies.get_all()
session_token = next(
    (c.value for c in cookies if c.name == "WorkosCursorSessionToken"),
    None
)

from urllib.parse import unquote
token_decoded = unquote(session_token) if session_token else None

# Save to file
with open("session_tokens.txt", "a") as f:
    f.write(f"{email}\t+{phone}\t{stripe_url}\t{token_decoded}\n")
print("Saved to session_tokens.txt")

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


# %% [20] Cleanup (run when done)
await browser.cookies.clear()
await browser.stop()
print("Browser closed")

# %%
