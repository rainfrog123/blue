# %% 1. IMPORTS & SETUP
import os
import sys
import time
import zendriver as zd

# Add herosms to path
sys.path.insert(0, "/allah/blue/web/auto/herosms")
import herosms

os.environ["DISPLAY"] = ":1"
print("✓ Imports loaded, DISPLAY=:1")

# %% 2. LAUNCH BROWSER & GO TO CURSOR.COM
browser = await zd.start(headless=False, sandbox=False, browser_args=["--disable-gpu"])
page = await browser.get("https://cursor.com")
print("✓ Browser launched - navigating to cursor.com")

# %% 3. WAIT FOR PAGE TO LOAD
await page.sleep(5)
print("✓ Page loaded")


# %% 4. CLICK SIGN IN (opens new tab)
sign_in_link = await page.find("Sign in")
await sign_in_link.click()
print("✓ Clicked Sign in")

# %% 5. GET NEW TAB & WAIT FOR SIGN IN PAGE
await page.sleep(3)
page = browser.tabs[-1]  # Get the newest tab (sign-in page)
await page.sleep(3)
print(f"✓ Sign in page loaded: {page.target.url}")

# %% 6. FILL EMAIL & CONTINUE
email_input = await page.select('input[type="email"]')
await email_input.send_keys("poam@ceto.site")
print("✓ Email filled: poam@ceto.site")

continue_btn = await page.find("Continue")
await continue_btn.click()
print("✓ Clicked Continue")

# %% 7. WAIT & CLICK EMAIL SIGN-IN CODE
await page.sleep(5)
email_code_btn = await page.find("Email sign-in code")
await email_code_btn.click()
print("✓ Clicked Email sign-in code")

# %% 8. WAIT FOR CODE INPUT
await page.sleep(3)
print("✓ OTP input page loaded")

# %% 9. FILL OTP CODE
otp_code = "882932"
for i, digit in enumerate(str(otp_code)):
    otp_input = await page.select(f'input[data-index="{i}"]')
    await otp_input.send_keys(digit)
    await page.sleep(0.2)
print(f"✓ OTP filled: {otp_code}")

# %% 10. WAIT FOR PHONE VERIFICATION PAGE
await page.sleep(5)
await page.save_screenshot("cursor_phone_page.png")
print("✓ Phone verification page loaded")

# %% 11. GET PHONE NUMBER FROM HEROSMS
print(f"HeroSMS Balance: ${herosms.get_balance()}")

# Get Philippines phone number (country=4, service="ot" for other)
COUNTRY_ID = 4    # Philippines
SERVICE = "ot"    # Any other service
activation_id, phone = herosms.get_number(service=SERVICE, country=COUNTRY_ID)
print(f"✓ Got number: +{phone} (ID: {activation_id})")

# Parse phone - remove country code prefix (63 for Philippines)
phone_local = phone[2:] if phone.startswith("63") else phone
print(f"✓ Local number: {phone_local}")

# %% 12. FILL PHONE NUMBER FORM
# Set country code to +63 for Philippines using JavaScript (bypasses formatting)
COUNTRY_CODE = "+63"
await page.evaluate(f'''
    const countryInput = document.querySelector('input[name="country_code"]');
    countryInput.value = "{COUNTRY_CODE}";
    countryInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
''')
print(f"✓ Country code: {COUNTRY_CODE}")

# Fill local number using JavaScript (bypasses auto-formatting)
await page.evaluate(f'''
    const localInput = document.querySelector('input[name="local_number"]');
    localInput.value = "{phone_local}";
    localInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
''')
print(f"✓ Local number filled: {phone_local}")

# Click send verification code
send_code_btn = await page.find("Send verification code")
await send_code_btn.click()
print("✓ Clicked Send verification code")

# Mark ready to receive SMS
herosms.mark_ready(activation_id)
print("✓ Marked ready for SMS")

# %% 13. WAIT FOR SMS CODE
print("\nPolling for SMS code...")
sms_code = None
for i in range(60):  # Wait up to 5 minutes
    status = herosms.get_status(activation_id)
    print(f"[{i*5:3d}s] {status}")
    
    if status.startswith("STATUS_OK:"):
        sms_code = status.split(":")[1]
        print(f"\n*** SMS CODE RECEIVED: {sms_code} ***")
        break
    elif status == "STATUS_CANCEL":
        print("\nActivation was cancelled")
        break
    
    time.sleep(5)

if not sms_code:
    print("Timeout - no code received")
    herosms.cancel(activation_id)
    raise Exception("SMS code timeout")

# %% 14. ENTER SMS VERIFICATION CODE
await page.sleep(2)
# Look for OTP input fields (similar to email OTP)
for i, digit in enumerate(str(sms_code)):
    try:
        otp_input = await page.select(f'input[data-index="{i}"]')
        await otp_input.send_keys(digit)
        await page.sleep(0.2)
    except:
        # Try alternative selector
        code_input = await page.select('input[type="tel"]')
        await code_input.send_keys(sms_code)
        break
print(f"✓ SMS code filled: {sms_code}")

# Complete the activation
herosms.complete(activation_id)
print("✓ HeroSMS activation completed")

# %% 15. WAIT FOR LOGIN TO COMPLETE
await page.sleep(5)
await page.save_screenshot("cursor_logged_in.png")
print("✓ Screenshot saved: cursor_logged_in.png")

# %% 16. GET CURRENT COOKIES
cookies = await browser.cookies.get_all()
print(f"✓ Found {len(cookies)} cookies:")
for cookie in cookies:
    # print(f"  - {cookie.name}: {cookie.value[:50]}..." if len(cookie.value) > 50 else f"  - {cookie.name}: {cookie.value}")
# i want WorkosCursorSessionToken
    # Print the WorkosCursorSessionToken if present in the cookies
    for cookie in cookies:
        if cookie.name == "WorkosCursorSessionToken":
            print(f"WorkosCursorSessionToken: {cookie.value}")
            break
# %% 17. CLOSE BROWSER (run when done)
await browser.stop()
print("✓ Browser closed")
