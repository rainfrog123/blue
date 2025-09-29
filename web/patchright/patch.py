# visit_google_async.py
import asyncio
from patchright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            channel="chrome",
            proxy={
                "server": "https://gb.decodo.com:30001",
                "username": "sp3j58curv",
                "password": "9oOoKQ8+z8pkcUsnv0"
            }
        )
        page = await browser.new_page()
        await page.goto("https://www.google.com/search?q=1", wait_until="load", timeout=30_000)
        
        # Get page title
        title = await page.title()
        print("Page title:", title)
        
        # Check for common access block indicators
        page_content = await page.content()
        
        # Look for specific block messages
        block_indicators = [
            "having trouble accessing",
            "unusual traffic",
            "automated queries",
            "sorry, but your computer",
            "blocked",
            "captcha",
            "verify you're not a robot",
            "click here to continue",
            "send feedback"
        ]
        
        found_blocks = []
        for indicator in block_indicators:
            if indicator.lower() in page_content.lower():
                found_blocks.append(indicator)
        
        if found_blocks:
            print("🚫 ACCESS BLOCK DETECTED:")
            for block in found_blocks:
                print(f"   - Found: '{block}'")
        else:
            print("✅ No obvious access blocks detected")
        
        # Get visible text content
        body_text = await page.text_content("body")
        if body_text:
            print(f"\nPage text preview (first 300 chars):")
            print(body_text[:300] + "..." if len(body_text) > 300 else body_text)
        
        # Check if we can find search results
        search_results = await page.query_selector_all("[data-ved]")  # Google search result elements
        print(f"\nSearch results found: {len(search_results)} elements")
        
        # Check current URL (redirects can indicate blocks)
        current_url = page.url
        print(f"Current URL: {current_url}")
        if "google.com/search" not in current_url:
            print("⚠️  URL changed - possible redirect due to blocking")
        
        # Take screenshot
        await page.screenshot(path="google_headless_async.png", full_page=True)
        print("Screenshot saved as google_headless_async.png")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
