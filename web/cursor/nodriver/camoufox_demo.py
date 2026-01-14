# %% 1. IMPORTS - Run this first
from camoufox.sync_api import Camoufox
from camoufox.async_api import AsyncCamoufox
import os

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. START CAMOUFOX (SYNC) - Opens anti-detect Firefox in VNC
with Camoufox(headless=False) as browser:
    page = browser.new_page()
    page.goto("https://example.com")
    print(f"✓ Title: {page.title()}")
    print(f"✓ URL: {page.url}")
    input("Press Enter to close browser...")

# %% 3. CHECK FINGERPRINT - Visit BrowserScan to test anti-detect
with Camoufox(headless=False) as browser:
    page = browser.new_page()
    page.goto("https://www.browserscan.net/")
    page.wait_for_timeout(5000)
    print("✓ Check VNC to see BrowserScan results!")
    input("Press Enter to close browser...")

# %% 4. CUSTOM FINGERPRINT - Spoof OS and screen size
with Camoufox(
    headless=False,
    os="windows",  # Spoof as Windows
    screen={"width": 1920, "height": 1080},
) as browser:
    page = browser.new_page()
    page.goto("https://www.browserscan.net/")
    page.wait_for_timeout(5000)
    print("✓ Spoofed as Windows! Check VNC.")
    input("Press Enter to close browser...")

# %% 5. WITH PROXY - Use a proxy server
# Uncomment and set your proxy
# with Camoufox(
#     headless=False,
#     proxy={"server": "http://proxy.example.com:8080"},
# ) as browser:
#     page = browser.new_page()
#     page.goto("https://api.ipify.org")
#     print(f"✓ IP: {page.content()}")
#     input("Press Enter to close browser...")

print("✓ Proxy example commented out - uncomment and set your proxy to use")

# %% 6. ASYNC VERSION - For use with asyncio
import asyncio

async def async_camoufox_demo():
    async with AsyncCamoufox(headless=False) as browser:
        page = await browser.new_page()
        await page.goto("https://example.com")
        title = await page.title()
        print(f"✓ Async Title: {title}")
        await page.wait_for_timeout(3000)
    print("✓ Async demo complete!")

# Run async demo
asyncio.run(async_camoufox_demo())

# %% 7. GOOGLE SEARCH - Search with anti-detect
with Camoufox(headless=False) as browser:
    page = browser.new_page()
    page.goto("https://www.google.com")
    page.wait_for_timeout(2000)
    
    # Find and fill search box
    search_box = page.locator("textarea[name='q']")
    if search_box.count() > 0:
        search_box.fill("camoufox anti-detect browser")
        page.keyboard.press("Enter")
        page.wait_for_timeout(3000)
        print("✓ Google search performed! Check VNC.")
    else:
        print("✗ Search box not found")
    
    input("Press Enter to close browser...")

# %% 8. TAKE SCREENSHOT - Save page as image
with Camoufox(headless=False) as browser:
    page = browser.new_page()
    page.goto("https://www.browserscan.net/")
    page.wait_for_timeout(5000)
    page.screenshot(path="camoufox_screenshot.png", full_page=True)
    print("✓ Screenshot saved to camoufox_screenshot.png")

# %% 9. MULTIPLE PAGES - Open multiple tabs
with Camoufox(headless=False) as browser:
    page1 = browser.new_page()
    page1.goto("https://example.com")
    print(f"✓ Tab 1: {page1.url}")
    
    page2 = browser.new_page()
    page2.goto("https://www.google.com")
    print(f"✓ Tab 2: {page2.url}")
    
    # Switch to first tab
    page1.bring_to_front()
    print("✓ Switched to Tab 1")
    
    input("Press Enter to close browser...")

# %% 10. HUMANIZE CURSOR - Enable human-like mouse movements
with Camoufox(
    headless=False,
    humanize=True,  # Enable human-like cursor movements
) as browser:
    page = browser.new_page()
    page.goto("https://www.google.com")
    page.wait_for_timeout(2000)
    
    # Human-like click on search box
    search_box = page.locator("textarea[name='q']")
    if search_box.count() > 0:
        search_box.click()  # Will move mouse naturally
        page.keyboard.type("hello world", delay=100)  # Type with delay
        page.wait_for_timeout(2000)
        print("✓ Human-like typing complete!")
    
    input("Press Enter to close browser...")

# %% 11. PERSISTENT CONTEXT - Save cookies/session
import tempfile

user_data_dir = tempfile.mkdtemp()
print(f"✓ User data dir: {user_data_dir}")

with Camoufox(
    headless=False,
    persistent_context=True,
    user_data_dir=user_data_dir,
) as browser:
    page = browser.new_page()
    page.goto("https://example.com")
    print("✓ Persistent context - cookies will be saved!")
    input("Press Enter to close browser...")

# %% 12. BLOCK WEBRTC - Prevent IP leaks
with Camoufox(
    headless=False,
    block_webrtc=True,  # Block WebRTC to prevent IP leaks
) as browser:
    page = browser.new_page()
    page.goto("https://browserleaks.com/webrtc")
    page.wait_for_timeout(5000)
    print("✓ WebRTC should be blocked! Check VNC.")
    input("Press Enter to close browser...")
