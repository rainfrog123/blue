# %% [1] Initialize & Configure
import random
import subprocess
import time
import asyncio
from playwright.async_api import async_playwright

from api_client import get_api, api_get, api_post, create_profile
from config import verify_paths

# === CONFIGURATION ===
PROFILE_OS = "android"
DEBUG_PORT = 6394
DIRECT_STRIPE_URL = "https://checkout.stripe.com/c/pay/cs_live_a1VrXYcx0VV9dZxDTU5NidrhFg2mHFP0nXEYDfaLlpQBQTs7t57BIqoRtr#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEnKSd2cGd2ZndsdXFsamtQa2x0cGBrYHZ2QGtkZ2lgYSc%2FY2RpdmApJ2R1bE5gfCc%2FJ3VuWmlsc2BaMDRJZzBJf0cxUV9SfVZMQlAxSWZkV3xzUTB9UjRMcj1fNkA0bEp1cEZnaUdJakltanQ2fVRrcTdQM3ZXNW5jdzNyclFhSWFURnxuY39La3IyMj1VZEoyazc1NXF2V2hTYDI3JyknY3dqaFZgd3Ngdyc%2FcXdwYCknZ2RmbmJ3anBrYUZqaWp3Jz8nJjU1NTU1NScpJ2lkfGpwcVF8dWAnPyd2bGtiaWBabHFgaCcpJ2BrZGdpYFVpZGZgbWppYWB3dic%2FcXdwYHgl"

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
    """Human-like click - uses tap() for Android compatibility."""
    p = page_ref or page
    await scroll_into_view(element, p)
    await asyncio.sleep(random.uniform(0.1, 0.3))
    
    # Use tap() for Android - avoids long-press issues
    try:
        await element.tap()
    except:
        await element.click()


async def human_type_slow(element, text, page_ref=None, typo_chance=0.05):
    """Type text char-by-char with small delays."""
    p = page_ref or page
    await scroll_into_view(element, p)
    
    # Tap to focus (Android-safe)
    try:
        await element.tap()
    except:
        await element.click()
    
    await asyncio.sleep(random.uniform(0.2, 0.4))
    
    # Clear existing content
    await element.fill("")
    await asyncio.sleep(random.uniform(0.1, 0.2))
    
    # Type char by char
    for char in str(text):
        await p.keyboard.type(char, delay=random.randint(50, 120))
        if random.random() < 0.08:
            await asyncio.sleep(random.uniform(0.1, 0.3))
    
    await asyncio.sleep(random.uniform(0.2, 0.4))


async def human_type(element, text, page_ref=None):
    """Alias for human_type_slow (backward compat)."""
    await human_type_slow(element, text, page_ref)


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


async def human_scroll(page_ref=None, direction="down", amount=None):
    """Scroll like a human reading the page."""
    p = page_ref or page
    scroll_amount = amount or random.randint(100, 300)
    if direction == "up":
        scroll_amount = -scroll_amount
    await p.mouse.wheel(0, scroll_amount)
    await asyncio.sleep(random.uniform(0.3, 0.7))


async def human_tab_to_next(page_ref=None):
    """Press Tab to move to next field (like real users)."""
    p = page_ref or page
    await asyncio.sleep(random.uniform(0.1, 0.3))
    await p.keyboard.press("Tab")
    await asyncio.sleep(random.uniform(0.2, 0.5))

# === VERIFY ENVIRONMENT ===
print("Verifying paths...")
if not verify_paths():
    raise RuntimeError("Missing required files")

resp = api_get("/api/v2/client/themes", timeout=3)
if resp.get("error"):
    raise RuntimeError(f"OctoBrowser not running: {resp['error']}")

print(f"✓ OctoBrowser API: {get_api()}")
print(f"Config: {PROFILE_OS} | Port: {DEBUG_PORT}")


# %% [2] (Direct Stripe mode - no session needed)
print("✓ Direct Stripe mode")


# %% [3] Create Profile
title = f"Dashboard-{PROFILE_OS.title()}-{int(time.time())}"

result = create_profile(
    title=title,
    os_type=PROFILE_OS,
    proxy_url=None,
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


# %% [7] Navigate to Stripe
# Skip if already on Stripe
if "stripe" in page.url or "checkout" in page.url:
    print(f"✓ Already on Stripe: {page.url[:60]}...")
else:
    print(f"Navigating to Stripe checkout...")
    await page.goto(DIRECT_STRIPE_URL, timeout=20000)
    await page.wait_for_load_state("load")
    await asyncio.sleep(random.uniform(2, 3))
    print(f"✓ On Stripe: {page.url[:60]}...")


# %% [8] Click Card Payment Method
# Human: scan page first
await human_mouse_moves(count=2)
await asyncio.sleep(random.uniform(0.5, 1))

# Click Card option
card_option = page.locator('[data-testid="card-accordion-item"]').or_(
    page.locator('text="Card"')
)

try:
    await card_option.first.wait_for(state="visible", timeout=20000)
    await human_click(card_option.first)
    print("✓ Clicked Card")
    await asyncio.sleep(random.uniform(1, 2))
except Exception as e:
    print(f"? Card: {e} (may already be selected)")


# %% [9] Fill Stripe Form
DEBUG = True  # True = use test card, False = prompt for input

# === READING THE PAGE (real users read price, terms first) ===
await asyncio.sleep(random.uniform(3, 5))  # longer initial read
await human_mouse_moves(count=3)

# Maybe look at the price/details area (top right usually)
viewport = page.viewport_size
if viewport and random.random() < 0.6:
    await page.mouse.move(
        random.randint(int(viewport["width"] * 0.6), int(viewport["width"] * 0.85)),
        random.randint(50, 150)
    )
    await asyncio.sleep(random.uniform(1, 2))  # reading price

await asyncio.sleep(random.uniform(0.5, 1))

# Prepare data
german_first_names = ["Maximilian", "Alexander", "Felix", "Lukas", "Paul", "Leon", "Jonas", "Finn", "Elias", "Noah", "Sophie", "Marie", "Emma", "Hannah", "Mia", "Anna", "Lea", "Lena", "Laura", "Julia"]
german_last_names = ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz", "Hoffmann", "Koch", "Richter", "Klein", "Wolf", "Schröder", "Neumann", "Schwarz", "Braun", "Hofmann", "Zimmermann"]

cardholder_name = f"{random.choice(german_first_names)} {random.choice(german_last_names)}"
print(f"✓ Generated name: {cardholder_name}")

billing_address = {
    "country": "DE",
    "address_line1": "Braubachstraße 41",
    "city": "Frankfurt am Main",
    "postal_code": "60311",
}

if DEBUG:
    card_number = "5229434513661509"
    card_expiry = "0430"
    card_cvc = "682"
    print(f"Card: {card_number[:4]}...{card_number[-4:]}")
else:
    print("Enter card details:")
    card_number = input("Card Number (16 digits): ").strip().replace(" ", "")
    card_expiry = input("Expiry (MMYY, no slash): ").strip().replace("/", "")
    card_cvc = input("CVC (3-4 digits): ").strip()

print(f"Card: {card_number[:4]}...{card_number[-4:]} | Expiry: {card_expiry} | CVC: {'*' * len(card_cvc)}")

# === 1. CARD INFORMATION (top of form) ===
await asyncio.sleep(random.uniform(0.8, 1.5))

# Card number - type VERY slowly (sensitive data, user double-checks)
card_input = page.locator('#cardNumber')
await human_type_slow(card_input, card_number, typo_chance=0.02)
print("✓ Filled card number")

# Sometimes pause to visually verify card number
if random.random() < 0.3:
    await asyncio.sleep(random.uniform(0.8, 1.5))  # "did I type that right?"

# Tab to expiry (card forms almost always use Tab)
await human_tab_to_next()

# Expiry - Stripe auto-formats with slash
expiry_input = page.locator('#cardExpiry')
await human_type_slow(expiry_input, card_expiry, typo_chance=0.02)
print("✓ Filled expiry")

# Tab to CVC
await human_tab_to_next()

# CVC - quick glance at back of card
await asyncio.sleep(random.uniform(0.3, 0.8))
cvc_input = page.locator('#cardCvc')
await human_type_slow(cvc_input, card_cvc, typo_chance=0.01)
print("✓ Filled CVC")

# Pause after card info (sensitive section done)
await asyncio.sleep(random.uniform(1, 2))

# === 2. CARDHOLDER NAME ===
name_input = page.locator('#billingName')
await human_type_slow(name_input, cardholder_name, typo_chance=0.05)
print(f"✓ Filled name: {cardholder_name}")

await asyncio.sleep(random.uniform(0.5, 1))

# === 3. BILLING ADDRESS ===
# Country - type to search (more human than just selecting)
country_select = page.locator('#billingCountry')
await human_click(country_select, hover_first=True)
await asyncio.sleep(random.uniform(0.4, 0.8))

# Type "Ger" to search, then select (like real user)
if random.random() < 0.6:
    await page.keyboard.type("Ger", delay=random.randint(100, 200))
    await asyncio.sleep(random.uniform(0.3, 0.6))
await country_select.select_option(value="DE")
print("✓ Selected country: Germany")
await asyncio.sleep(random.uniform(0.8, 1.5))

# Address line 1
addr_input = page.locator('#billingAddressLine1')
await human_type_slow(addr_input, billing_address["address_line1"], typo_chance=0.05)
print(f"✓ Filled address: {billing_address['address_line1']}")

# Tab through Address line 2 (optional field, skip it)
await human_tab_to_next()
await asyncio.sleep(random.uniform(0.2, 0.4))  # brief pause on empty field
await human_tab_to_next()  # skip to postal code

# Maybe scroll to see postal/city
if random.random() < 0.4:
    await human_scroll(direction="down", amount=random.randint(50, 100))

# Postal code
postal_input = page.locator('#billingPostalCode')
await human_type_slow(postal_input, billing_address["postal_code"], typo_chance=0.03)
print(f"✓ Filled postal code: {billing_address['postal_code']}")

# Tab to city
await human_tab_to_next()

# City
city_input = page.locator('#billingLocality')
await human_type_slow(city_input, billing_address["city"], typo_chance=0.06)
print(f"✓ Filled city: {billing_address['city']}")

# === REVIEW BEHAVIOR (real users double-check before paying) ===
await asyncio.sleep(random.uniform(1.5, 2.5))

# Scroll up to review card info
if random.random() < 0.5:
    await human_scroll(direction="up", amount=random.randint(100, 200))
    await asyncio.sleep(random.uniform(1, 2))  # reading/verifying
    
# Maybe click on card field to re-verify (common behavior)
if random.random() < 0.25:
    card_field = page.locator('#cardNumber')
    await human_click(card_field)
    await asyncio.sleep(random.uniform(0.5, 1))
    await page.keyboard.press("End")  # move cursor to end
    await asyncio.sleep(random.uniform(0.3, 0.6))

# Final mouse movements (looking at submit button area)
await human_mouse_moves(count=2)
await asyncio.sleep(random.uniform(0.5, 1))
print("\n" + "="*50)
print("FORM COMPLETE - Ready to submit")
print("="*50)


# %% [10] Keep Browser Open
# The browser stays open for manual inspection
# Run cleanup cell when done
print("\nBrowser is open. Run next cell to cleanup when done.")


# %% [11] Cleanup
print("Cleaning up...")

if browser:
    await browser.close()

if playwright:
    await playwright.stop()

if profile_uuid:
    api_post("/api/profiles/stop", {"uuid": profile_uuid}, timeout=5)
    print(f"  Profile stopped")

print("✓ Done")
