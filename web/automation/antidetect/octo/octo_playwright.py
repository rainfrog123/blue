#!/usr/bin/env python3
"""
OctoBrowser + Playwright Automation Example
"""
import requests
from playwright.sync_api import sync_playwright

OCTO_API = "http://localhost:51639"
PROFILE_UUID = "51083d3a5c2b44dbb993ae6fa416e634"


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


def main():
    # Start profile and get WebSocket endpoint
    ws_endpoint = start_profile(PROFILE_UUID)
    
    if not ws_endpoint:
        print("Error: No WebSocket endpoint returned")
        return
    
    # Connect Playwright to the running browser
    with sync_playwright() as p:
        # Connect to existing browser via CDP
        browser = p.chromium.connect_over_cdp(ws_endpoint)
        
        # Get the default context (OctoBrowser's context with fingerprint)
        context = browser.contexts[0]
        
        # Get existing page or create new one
        if context.pages:
            page = context.pages[0]
        else:
            page = context.new_page()
        
        # Example automation
        print("\n=== Automating browser ===")
        
        # Navigate to a page
        page.goto("https://example.com")
        print(f"Title: {page.title()}")
        
        # Take a screenshot
        page.screenshot(path="/root/screenshot.png")
        print("Screenshot saved to /root/screenshot.png")
        
        # Example: Fill a form, click buttons, etc.
        # page.fill('input[name="q"]', 'test query')
        # page.click('button[type="submit"]')
        
        # Don't close - leave browser open
        # browser.close()
    
    print("\nDone! Browser is still running.")
    print(f"Stop with: curl -X POST {OCTO_API}/api/profiles/stop -H 'Content-Type: application/json' -d '{{\"uuid\": \"{PROFILE_UUID}\"}}'")


if __name__ == "__main__":
    main()
