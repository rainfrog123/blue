# OctoBrowser Automation

Scripts and documentation for automating OctoBrowser via Playwright and the local API.

## Documentation index

| Document | Purpose |
|----------|---------|
| [LOCAL_API.md](LOCAL_API.md) | **Local API reference** — endpoints, create/start/stop profiles, examples |
| [RUNNING_OCTOBROWSER.md](RUNNING_OCTOBROWSER.md) | **Running OctoBrowser** — VNC, root, sandbox env vars, troubleshooting |
| [API_TIER_BYPASS.md](API_TIER_BYPASS.md) | Reverse engineering guide to bypass API tier restrictions |

## Scripts

| File | Purpose |
|------|---------|
| `octo_cursor.py` | **Cursor account automation** — creates accounts with email/SMS verification |
| `octo_playwright.py` | Playwright automation script (basic example) |
| `octo_playwright_nb.py` | Notebook-friendly version |
| `octo_commands.sh` | Shell helpers for API (list, start, stop, create profile) |

## Quick start

### 1. Start OctoBrowser (VNC, as root)

```bash
# Option A: Use the helper script
/allah/blue/web/auto/octo/hid/spoof_hid.sh --start

# Option B: Run directly
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox
```

See [RUNNING_OCTOBROWSER.md](RUNNING_OCTOBROWSER.md) for details.

### 2. Create and start a profile via API

```bash
# Create profile
curl -s -X POST "http://localhost:56933/api/v2/profiles/quick" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Profile", "os": "win"}' | python3 -m json.tool

# List profiles
curl -s -X POST "http://localhost:56933/api/v2/profiles/list" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool

# Start profile (replace UUID from create response)
curl -s -X POST "http://localhost:56933/api/v2/profiles/YOUR_UUID_HERE/start" \
  -H "Content-Type: application/json" \
  -d '{}'

# Stop profile
curl -s -X POST "http://localhost:56933/api/v2/profiles/YOUR_UUID_HERE/stop" \
  -H "Content-Type: application/json" \
  -d '{}'
```

See [LOCAL_API.md](LOCAL_API.md) for full API reference.

### 3. Shell helpers (optional)

```bash
cd /allah/blue/web/auto/octo/automation
source octo_commands.sh
octo_list
octo_create "My Profile"
octo_start YOUR_UUID_HERE
octo_stop YOUR_UUID_HERE
```

## Cursor Account Automation

Automated Cursor account creation with email/SMS verification:

```bash
# Run as Python script (or use as notebook with % cell markers)
/allah/freqtrade/.venv/bin/python3 octo_cursor.py
```

Features:
- Creates fresh OctoBrowser profile with randomized fingerprint
- Generates email using prefixes from `hyas_prefixes.txt`
- Polls Cloudflare Worker for email verification codes
- Uses HeroSMS for phone verification
- Captures Stripe checkout URL and session token
- Saves results to `session_tokens.txt`

**Dependencies:**
- `/allah/blue/web/auto/herosms/` - HeroSMS API wrapper (shared)
- `/allah/blue/web/auto/worker/hyas_prefixes.txt` - Email prefixes (shared)
- Cursor email worker at `https://cursor-email-worker.jar711red.workers.dev`

## Playwright (Basic Example)

```bash
python3 octo_playwright.py
```

Requires a profile to be started (e.g. via API or GUI) with a debug port if you need CDP/Playwright connection.

## Local API overview

- **Base:** `http://localhost:56933`
- **Prefix:** `/api/v2/`
- **Key endpoints:** `POST /api/v2/profiles/list`, `POST /api/v2/profiles/quick`, `POST /api/v2/profiles/{uuid}/start`, `POST /api/v2/profiles/{uuid}/stop`

```bash
# Test if API is up
curl -s http://localhost:56933/api/v2/client/themes | python3 -m json.tool
```

Full details: [LOCAL_API.md](LOCAL_API.md).

## Files summary

```
automation/
├── README.md                 # This index
├── LOCAL_API.md              # Local API reference
├── RUNNING_OCTOBROWSER.md    # VNC, root, sandbox
├── API_TIER_BYPASS.md        # Tier bypass (reverse engineering)
├── octo_commands.sh          # Shell helpers
├── octo_cursor.py            # Cursor account automation
├── octo_playwright.py        # Playwright script (basic example)
└── octo_playwright_nb.py     # Playwright notebook version

Shared dependencies (under /allah/blue/web/auto/):
├── herosms/herosms.py        # HeroSMS API wrapper
└── worker/hyas_prefixes.txt  # Email prefixes for @hyas.site
```
