# %% 1. IMPORTS & SETUP
from camoufox.async_api import AsyncCamoufox
from browserforge.fingerprints import Screen
import os

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. LAUNCH SUPER STEALTH BROWSER
browser = await AsyncCamoufox(
    headless=False,
    
    # Anti-fingerprinting
    block_webrtc=True,          # Block WebRTC IP leaks
    
    # Humanization
    humanize=True,              # Human-like mouse movements
    
    # Geolocation spoofing based on IP
    geoip=True,
    
    # Screen constraints (generates realistic fingerprint within range)
    screen=Screen(min_width=1920, max_width=1920, min_height=1080, max_height=1080),
    
).__aenter__()

page = await browser.new_page()
print("✓ Super stealth browser launched!")

# %% 3. TEST 1: CREEPJS - Most comprehensive fingerprint test
print("\n🔍 TEST 1: CreepJS (Most thorough fingerprint analysis)")
await page.goto("https://abrahamjuliot.github.io/creepjs/")
await page.wait_for_timeout(15000)  # CreepJS takes time to analyze
print("✓ CreepJS loaded - Check VNC for trust score!")
print("  Look for: Trust Score, Lies, Bot detection")

# %% 4. TEST 2: BROWSERSCAN - Detailed browser fingerprint
print("\n🔍 TEST 2: BrowserScan")
await page.goto("https://www.browserscan.net/")
await page.wait_for_timeout(8000)
print("✓ BrowserScan loaded - Check VNC!")
print("  Look for: Browser fingerprint uniqueness, WebRTC, Canvas")

# %% 5. TEST 3: PIXELSCAN - Bot detection test
print("\n🔍 TEST 3: PixelScan (Bot Detection)")
await page.goto("https://pixelscan.net/")
await page.wait_for_timeout(10000)
print("✓ PixelScan loaded - Check VNC!")

# %% 6. TEST 4: BROWSERLEAKS WEBRTC
print("\n🔍 TEST 4: BrowserLeaks WebRTC (IP Leak Test)")
await page.goto("https://browserleaks.com/webrtc")
await page.wait_for_timeout(5000)
print("✓ WebRTC test loaded - Should show NO LEAK!")

# %% 7. TEST 5: BROWSERLEAKS CANVAS
print("\n🔍 TEST 5: BrowserLeaks Canvas (Canvas Fingerprint)")
await page.goto("https://browserleaks.com/canvas")
await page.wait_for_timeout(5000)
print("✓ Canvas fingerprint test loaded!")

# %% 8. TEST 6: INCOLUMITAS BOT DETECTION
print("\n🔍 TEST 6: Incolumitas Bot Detection")
await page.goto("https://bot.incolumitas.com/")
await page.wait_for_timeout(10000)
print("✓ Bot detection test loaded!")

# %% 9. GET BROWSER FINGERPRINT INFO
info = await page.evaluate("""
    () => ({
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        webdriver: navigator.webdriver,
        plugins: navigator.plugins.length,
        screenRes: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        touchPoints: navigator.maxTouchPoints
    })
""")
print("\n📊 BROWSER FINGERPRINT:")
for k, v in info.items():
    print(f"  {k}: {v}")

# %% 10. SUMMARY
print("\n" + "="*50)
print("✓ All stealth tests complete! Check VNC.")
print("="*50)

# %% 11. CLOSE BROWSER (run when done)
await browser.close()
print("✓ Browser closed")
