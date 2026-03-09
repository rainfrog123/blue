# %% [markdown]
# # OctoBrowser + Playwright Automation
# Interactive notebook for controlling OctoBrowser profiles with Playwright

# %%
import requests
from playwright.sync_api import sync_playwright

OCTO_API = "http://localhost:51639"
PROFILE_UUID = "51083d3a5c2b44dbb993ae6fa416e634"

# %% [markdown]
# ## Helper Functions

# %%
def start_profile(uuid, debug_port=True):
    """Start OctoBrowser profile and get WebSocket endpoint"""
    # Stop if already running
    requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": uuid})
    
    # Start with debug port
    resp = requests.post(
        f"{OCTO_API}/api/profiles/start",
        json={"uuid": uuid, "debug_port": debug_port}
    )
    data = resp.json()
    print(f"Profile started: PID {data.get('browser_pid')}")
    print(f"WebSocket: {data.get('ws_endpoint')}")
    return data.get("ws_endpoint")


def stop_profile(uuid):
    """Stop OctoBrowser profile"""
    requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": uuid})
    print("Profile stopped")

# %% [markdown]
# ## Start Profile

# %%
ws_endpoint = start_profile(PROFILE_UUID)
print(f"\nWebSocket endpoint: {ws_endpoint}")

# %% [markdown]
# ## Connect Playwright

# %%
playwright = sync_playwright().start()
browser = playwright.chromium.connect_over_cdp(ws_endpoint)
context = browser.contexts[0]

# Get existing page or create new one
if context.pages:
    page = context.pages[0]
else:
    page = context.new_page()

print(f"Connected! Pages: {len(context.pages)}")

# %% [markdown]
# ## Automation Examples

# %%
# Navigate to a page
page.goto("https://example.com")
print(f"Title: {page.title()}")

# %%
# Take a screenshot
page.screenshot(path="/root/screenshot.png")
print("Screenshot saved to /root/screenshot.png")

# %%
# Example: Navigate somewhere else
# page.goto("https://google.com")
# page.fill('textarea[name="q"]', 'test query')
# page.keyboard.press("Enter")

# %%
# Example: Get page content
# html = page.content()
# print(html[:500])

# %% [markdown]
# ## Cleanup

# %%
# Disconnect Playwright (keeps browser open)
browser.close()
playwright.stop()
print("Playwright disconnected")

# %%
# Stop the profile completely (closes browser)
# stop_profile(PROFILE_UUID)
