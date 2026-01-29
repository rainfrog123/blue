# %% 1. IMPORTS & SETUP
import os
import zendriver as zd

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. LAUNCH BROWSER
browser = await zd.start(headless=False, sandbox=False, browser_args=["--disable-gpu"])
page = await browser.get("https://www.browserscan.net/bot-detection")
print("✓ Browser launched - Check VNC!")

# %% 3. BOT DETECTION TEST
print("\n🔍 TEST: BrowserScan Bot Detection")
await page.sleep(10)
await page.save_screenshot("browserscan.png")
print("✓ Screenshot saved: browserscan.png")

# %% 4. GET BROWSER FINGERPRINT INFO
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

# %% 5. CLOSE BROWSER (run when done)
await browser.stop()
print("✓ Browser closed")
