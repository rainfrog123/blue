# %% 1. IMPORTS - Run this first
import nodriver as uc
import os

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. START BROWSER - Opens Chrome in VNC
browser = await uc.start(
    headless=False,
    browser_args=[
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--window-size=1280,720",
        "--disable-webrtc",
        "--enforce-webrtc-ip-permission-check",``
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ]
)
print("✓ Browser started! Check VNC.")

# %% 3. NAVIGATE - Go to example.com
page = await browser.get("https://example.com")
print(f"✓ Navigated to: {page.url}")

# %% 4. GET PAGE TITLE - Read title via JavaScript
title = await page.evaluate("document.title")
print(f"✓ Page title: {title}")

# %% 5. FIND H1 ELEMENT - Select by CSS
h1 = await page.select("h1")
if h1:
    text = await h1.get_text()
    print(f"✓ H1 text: {text}")

# %% 6. FIND ALL LINKS - Get all <a> elements
links = await page.select_all("a")
print(f"✓ Found {len(links)} links")
for link in links:
    href = await link.get_attribute("href")
    text = await link.get_text()
    print(f"  → {text}: {href}")

# %% 7. GO TO GOOGLE - Navigate to google.com
page = await browser.get("https://www.google.com")
await page.sleep(2)
print(f"✓ Navigated to: {page.url}")

# %% 8. GOOGLE SEARCH - Type and search
search_input = await page.select("textarea[name='q']")
if search_input:
    await search_input.send_keys("nodriver python")
    await page.sleep(1)
    await search_input.send_keys("\n")
    await page.sleep(2)
    print("✓ Search performed!")
else:
    print("✗ Search input not found")

# %% 9. SCREENSHOT - Save current page
await page.save_screenshot("screenshot.png")
print("✓ Screenshot saved to screenshot.png")

# %% 10. RUN JAVASCRIPT - Execute JS on page
info = await page.evaluate("""
    () => ({
        url: window.location.href,
        title: document.title,
        width: window.innerWidth,
        height: window.innerHeight
    })
""")
print(f"✓ Page info: {info}")

# %% 11. CHANGE BACKGROUND - Modify page via JS
await page.evaluate("document.body.style.backgroundColor = 'lightblue';")
print("✓ Changed background to lightblue!")

# %% 12. OPEN NEW TAB - Multiple tabs
page2 = await browser.get("https://example.com", new_tab=True)
await page2.sleep(1)
print(f"✓ New tab opened: {page2.url}")

# %% 13. SWITCH TABS - Bring first tab to front
await page.bring_to_front()
print("✓ Switched back to first tab")

# %% 14. CLOSE BROWSER - Stop browser instance
browser.stop()
print("✓ Browser closed")
