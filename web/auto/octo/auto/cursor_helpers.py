# %% [markdown]
# # Cursor Automation Helpers
# Email generation, SMS polling, OTP filling. Test each independently.

# %% Imports
import random
import time
import asyncio
import requests

from config import CONFIG, HEROSMS_PATH
import sys
if HEROSMS_PATH not in sys.path:
    sys.path.insert(0, HEROSMS_PATH)
import herosms

# Type hints (optional - only needed when using async functions)
try:
    from playwright.async_api import Page
except ImportError:
    Page = None  # Type hint only, not needed for sync functions

# %% Stop Signal (for breaking polls from another cell)
class StopSignal:
    _stop = False
    
    @classmethod
    def stop(cls):
        cls._stop = True
        print("Stop signal sent - polling will stop on next iteration")
    
    @classmethod
    def reset(cls):
        cls._stop = False
    
    @classmethod
    def check(cls):
        if cls._stop:
            cls._stop = False
            return True
        return False

def stop():
    """Stop any running poll - call from another cell"""
    StopSignal.stop()

# %% Generate Email
def generate_email(config=None):
    """Generate email using random available prefix, mark as used."""
    cfg = config or CONFIG
    prefixes_file = cfg["prefixes_file"]
    
    with open(prefixes_file, "r") as f:
        lines = f.readlines()
    
    available = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "# USED" not in line:
            available.append((i, stripped))
    
    if not available:
        raise RuntimeError(f"No available prefixes in {prefixes_file}")
    
    idx, prefix = random.choice(available)
    lines[idx] = f"{prefix} # USED\n"
    with open(prefixes_file, "w") as f:
        f.writelines(lines)
    
    email = f"{prefix}{cfg['email_domain']}"
    print(f"Generated email: {email}")
    return email

# %% Check Available Prefixes
def count_available_prefixes(config=None):
    """Count how many prefixes are still available"""
    cfg = config or CONFIG
    prefixes_file = cfg["prefixes_file"]
    
    with open(prefixes_file, "r") as f:
        lines = f.readlines()
    
    available = 0
    used = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if "# USED" in line:
                used += 1
            else:
                available += 1
    
    print(f"Prefixes: {available} available, {used} used")
    return available, used

# %% Poll Email Code
def poll_email_code(email_addr, timeout=300, interval=5, config=None):
    """Poll worker for email OTP code. Run stop() to break."""
    cfg = config or CONFIG
    url = cfg["email_worker_url"]
    
    print(f"Polling for email code: {email_addr}")
    print("  (Run `stop()` in another cell to break out)")
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
    
    raise TimeoutError(f"No code received in {timeout}s")

# %% HeroSMS: Get Phone Number
def get_phone_number(config=None):
    """Get a phone number from HeroSMS. Returns (activation_id, phone, phone_local)."""
    cfg = config or CONFIG
    
    print(f"HeroSMS Balance: ${herosms.get_balance()}")
    
    activation_id, phone = herosms.get_number(
        service=cfg["phone_service"],
        country=cfg["phone_country_id"]
    )
    
    country_code = cfg["phone_country_code"]
    phone_local = phone[len(country_code):] if phone.startswith(country_code) else phone
    
    print(f"Phone: +{phone} -> local: {phone_local}")
    herosms.mark_ready(activation_id)
    
    return activation_id, phone, phone_local

# %% HeroSMS: Format Phone
def format_phone_uk(phone_local):
    """Format UK phone number for input field"""
    if len(phone_local) >= 10:
        return f"({phone_local[:3]}){phone_local[3:6]}-{phone_local[6:]}"
    return phone_local

# %% Poll SMS Code
def poll_sms_code(activation_id, timeout=300, interval=5):
    """Poll HeroSMS for SMS code. Run stop() to break."""
    print("Polling for SMS code...")
    print("  (Run `stop()` in another cell to break out)")
    StopSignal.reset()
    
    for i in range(timeout // interval):
        if StopSignal.check():
            print("Stopped by user")
            return None
        
        status = herosms.get_status(activation_id)
        print(f"[{i * interval:3d}s] {status}")
        
        if status.startswith("STATUS_OK:"):
            code = status.split(":")[1]
            print(f"SMS CODE: {code}")
            return code
        elif status == "STATUS_CANCEL":
            raise Exception("SMS activation cancelled")
        
        time.sleep(interval)
    
    herosms.cancel(activation_id)
    raise TimeoutError(f"No SMS code in {timeout}s")

# %% Complete SMS Activation
def complete_sms(activation_id):
    """Mark SMS activation as complete"""
    herosms.complete(activation_id)
    print("HeroSMS activation completed")

# %% Cancel SMS Activation
def cancel_sms(activation_id):
    """Cancel SMS activation (refund)"""
    herosms.cancel(activation_id)
    print("HeroSMS activation cancelled")

# %% Async: Fill OTP Inputs
async def fill_otp(page, code: str, fallback: str = None):
    """Fill OTP inputs digit by digit"""
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

# %% Async: Set React Input
async def set_react_input(page, selector: str, value: str):
    """Set React controlled input with human-like typing"""
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

# %% Test: Check prefixes and HeroSMS balance
if __name__ == "__main__" or "get_ipython" in dir():
    print("=== Cursor Helpers Test ===\n")
    count_available_prefixes()
    print(f"\nHeroSMS Balance: ${herosms.get_balance()}")
