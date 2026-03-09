# OctoBrowser Automation

Scripts and documentation for automating OctoBrowser via Playwright and the local API.

## Documentation

| Document | Purpose |
|----------|---------|
| [LOCAL_API.md](../docs/LOCAL_API.md) | **Local API reference** — endpoints, create/start/stop profiles, examples |
| [RUNNING_OCTOBROWSER.md](../docs/RUNNING_OCTOBROWSER.md) | **Running OctoBrowser** — VNC, root, sandbox env vars, troubleshooting |

For reverse engineering (tier bypass, HID spoofing, SSL bypass), see [../reverse_engineering/](../reverse_engineering/).

## Scripts

| File | Purpose |
|------|---------|
| `cursor_automation.py` | **Main workflow** — run cells sequentially to create Cursor accounts |
| `config.py` | Configuration, paths, settings — test with `python config.py` |
| `octo_helpers.py` | OctoBrowser API functions — test with `python octo_helpers.py` |
| `cursor_helpers.py` | Email/SMS/OTP helpers — test with `python cursor_helpers.py` |

## Quick start

### 1. Start OctoBrowser (VNC, as root)

```bash
# Option A: Use the helper script
/allah/blue/web/auto/octo/reverse_engineering/hid/spoof_hid.sh --start

# Option B: Run directly
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox
```

See [RUNNING_OCTOBROWSER.md](../docs/RUNNING_OCTOBROWSER.md) for details.

### 2. Create and start a profile via API

```bash
# Create profile
curl -s -X POST "http://localhost:59999/api/v2/profiles/quick" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Profile", "os": "win"}' | python3 -m json.tool

# List profiles
curl -s -X POST "http://localhost:59999/api/v2/profiles/list" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool

# Start profile (replace UUID from create response)
curl -s -X POST "http://localhost:59999/api/v2/profiles/YOUR_UUID_HERE/start" \
  -H "Content-Type: application/json" \
  -d '{}'

# Stop profile
curl -s -X POST "http://localhost:59999/api/v2/profiles/YOUR_UUID_HERE/stop" \
  -H "Content-Type: application/json" \
  -d '{}'
```

See [LOCAL_API.md](../docs/LOCAL_API.md) for full API reference.

### 3. Shell one-liners

```bash
# Get port (changes each restart)
OCTO_PORT=$(cat ~/.Octo\ Browser/local_port)
OCTO="http://localhost:$OCTO_PORT"

# Check API is up
curl -s "$OCTO/api/v2/client/themes" | python3 -m json.tool

# List profiles
curl -s -X POST "$OCTO/api/v2/profiles/list" -H "Content-Type: application/json" -d '{}' | python3 -m json.tool

# Create profile (returns UUID)
curl -s -X POST "$OCTO/api/v2/profiles/quick" -H "Content-Type: application/json" -d '{"title": "Test", "os": "mac"}' | python3 -m json.tool

# Start profile (with debug port for Playwright)
curl -s -X POST "$OCTO/api/profiles/start" -H "Content-Type: application/json" -d '{"uuid": "YOUR_UUID", "debug_port": true}'

# Stop profile
curl -s -X POST "$OCTO/api/profiles/stop" -H "Content-Type: application/json" -d '{"uuid": "YOUR_UUID"}'

# Clone profile
curl -s -X POST "$OCTO/api/v2/profiles/YOUR_UUID/clone" -H "Content-Type: application/json" -d '{"amount": 3}' | python3 -m json.tool
```

## Cursor Account Automation

Modular automation with `# %%` cell markers for VS Code Interactive debugging.

### File Structure

```
automation/
├── config.py              # Paths & settings (test independently)
├── octo_helpers.py        # OctoBrowser API (test independently)
├── cursor_helpers.py      # Email/SMS helpers (test independently)
└── cursor_automation.py   # Main workflow (imports above)
```

### Usage in VS Code

1. Open `cursor_automation.py` in VS Code
2. Run cells with **Shift+Enter** (runs in Python Interactive window)
3. Each cell is independent — re-run any cell if it fails
4. Use `stop()` from another cell to break polling loops
5. Run `await debug_page()` anytime to screenshot current state

### Test Individual Modules

```bash
cd /allah/blue/web/auto/octo/automation

# Test config & paths
python config.py

# Test OctoBrowser helpers (lists profiles if Octo is running)
python octo_helpers.py

# Test cursor helpers (shows prefix count, HeroSMS balance)
python cursor_helpers.py
```

### Features

- Creates fresh OctoBrowser profile with randomized fingerprint
- Generates email using prefixes from `hyas_prefixes.txt`
- Polls Cloudflare Worker for email verification codes
- Uses HeroSMS for phone verification
- Captures Stripe checkout URL and session token
- Saves results to `session_tokens.txt`

### Dependencies

- `/allah/blue/web/auto/herosms/` - HeroSMS API wrapper (shared)
- `/allah/blue/web/auto/worker/hyas_prefixes.txt` - Email prefixes (shared)
- Cursor email worker at `https://cursor-email-worker.jar711red.workers.dev`

## Playwright + OctoBrowser (Basic Example)

Connect Playwright to an OctoBrowser profile via CDP (Chrome DevTools Protocol):

```python
import requests
from playwright.sync_api import sync_playwright

OCTO_API = "http://localhost:59999"  # Configured in start_octo.sh
PROFILE_UUID = "your-profile-uuid-here"

# Start profile with debug port enabled
requests.post(f"{OCTO_API}/api/profiles/stop", json={"uuid": PROFILE_UUID})
resp = requests.post(
    f"{OCTO_API}/api/profiles/start",
    json={"uuid": PROFILE_UUID, "debug_port": True}
)
ws_endpoint = resp.json().get("ws_endpoint")
print(f"WebSocket: {ws_endpoint}")

# Connect Playwright
with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp(ws_endpoint)
    context = browser.contexts[0]  # OctoBrowser's fingerprinted context
    page = context.pages[0] if context.pages else context.new_page()
    
    # Automate
    page.goto("https://example.com")
    print(f"Title: {page.title()}")
    page.screenshot(path="/tmp/screenshot.png")
```

For async Playwright (used in `cursor_automation.py`):

```python
from playwright.async_api import async_playwright

playwright = await async_playwright().start()
browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
context = browser.contexts[0]
page = context.pages[0] if context.pages else await context.new_page()

await page.goto("https://example.com")
print(await page.title())
```

## Local API overview

- **Base:** `http://localhost:59999`
- **Prefix:** `/api/v2/`
- **Key endpoints:** `POST /api/v2/profiles/list`, `POST /api/v2/profiles/quick`, `POST /api/v2/profiles/{uuid}/start`, `POST /api/v2/profiles/{uuid}/stop`

```bash
# Test if API is up
curl -s http://localhost:59999/api/v2/client/themes | python3 -m json.tool
```

Full details: [LOCAL_API.md](../docs/LOCAL_API.md).

## Files summary

```
automation/
├── README.md               # This file
├── config.py               # Configuration & paths
├── octo_helpers.py         # OctoBrowser API helpers
├── cursor_helpers.py       # Email/SMS/OTP helpers
├── cursor_automation.py    # Main workflow (27 cells)
└── session_tokens.txt      # Saved account tokens

Related:
├── ../docs/                # LOCAL_API.md, RUNNING_OCTOBROWSER.md
└── ../reverse_engineering/ # HID, SSL, storage, tier bypass

Shared (/allah/blue/web/auto/):
├── herosms/herosms.py            # HeroSMS API
└── worker/hyas_prefixes.txt      # Email prefixes
```
