# %% 1. IMPORTS - Run this first
from camoufox.async_api import AsyncCamoufox
import os

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. START CAMOUFOX - Opens anti-detect Firefox in VNC
browser = await AsyncCamoufox(headless=False).__aenter__()
page = await browser.new_page()
await page.goto("https://example.com")
print(f"✓ Title: {await page.title()}")
print(f"✓ URL: {page.url}")

# %% 3. CHECK FINGERPRINT - Visit BrowserScan to test anti-detect
await page.goto("https://www.browserscan.net/")
await page.wait_for_timeout(5000)
print("✓ Check VNC to see BrowserScan results!")

# %% 4. NAVIGATE TO BROWSERLEAKS - Check WebRTC
await page.goto("https://browserleaks.com/webrtc")
await page.wait_for_timeout(5000)
print("✓ Check WebRTC leak status in VNC!")

# %% 5. GOOGLE SEARCH - Search with anti-detect
await page.goto("https://www.google.com")
await page.wait_for_timeout(2000)

search_box = page.locator("textarea[name='q']")
if await search_box.count() > 0:
    await search_box.fill("camoufox anti-detect browser")
    await page.keyboard.press("Enter")
    await page.wait_for_timeout(3000)
    print("✓ Google search performed! Check VNC.")
else:
    print("✗ Search box not found")

# %% 6. SCREENSHOT - Save current page
await page.screenshot(path="camoufox_screenshot.png", full_page=True)
print("✓ Screenshot saved to camoufox_screenshot.png")

# %% 7. GET PAGE INFO - Execute JavaScript
info = await page.evaluate("""
    () => ({
        url: window.location.href,
        title: document.title,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages
    })
""")
print(f"✓ Page info: {info}")

# %% 8. NEW TAB - Open another page
page2 = await browser.new_page()
await page2.goto("https://example.com")
print(f"✓ New tab opened: {page2.url}")

# %% 9. SWITCH TABS - Go back to first tab
await page.bring_to_front()
print("✓ Switched back to first tab")

# %% 10. CLOSE BROWSER - Clean up
await browser.close()
print("✓ Browser closed")

# %% 11. CUSTOM FINGERPRINT - Spoof as Windows (new session)
browser2 = await AsyncCamoufox(
    headless=False,
    os="windows",
    screen={"width": 1920, "height": 1080},
).__aenter__()

page = await browser2.new_page()
await page.goto("https://www.browserscan.net/")
await page.wait_for_timeout(5000)
print("✓ Spoofed as Windows! Check VNC.")

# %% 12. CLOSE WINDOWS BROWSER
await browser2.close()
print("✓ Windows-spoofed browser closed")

# %% 13. BLOCK WEBRTC - Prevent IP leaks (new session)
browser3 = await AsyncCamoufox(
    headless=False,
    block_webrtc=True,
).__aenter__()

page = await browser3.new_page()
await page.goto("https://browserleaks.com/webrtc")
await page.wait_for_timeout(5000)
print("✓ WebRTC should be blocked! Check VNC.")

# %% 14. CLOSE WEBRTC BROWSER
await browser3.close()
print("✓ WebRTC-blocked browser closed")

# %% 15. HUMANIZE - Human-like cursor (new session)
browser4 = await AsyncCamoufox(
    headless=False,
    humanize=True,
).__aenter__()

page = await browser4.new_page()
await page.goto("https://www.google.com")
await page.wait_for_timeout(2000)

search_box = page.locator("textarea[name='q']")
if await search_box.count() > 0:
    await search_box.click()
    await page.keyboard.type("hello world", delay=100)
    await page.wait_for_timeout(2000)
    print("✓ Human-like typing complete!")

# %% 16. CLOSE HUMANIZE BROWSER
await browser4.close()
print("✓ Humanized browser closed")
