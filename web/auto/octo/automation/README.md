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
| `octo_playwright.py` | Playwright automation script |
| `octo_playwright_nb.py` | Notebook-friendly version |
| `octo_commands.sh` | Shell helpers for API (list, start, stop, create profile) |

## Quick start

### 1. Start OctoBrowser (VNC, as root)

```bash
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" /path/to/OctoBrowser.AppImage --no-sandbox
```

See [RUNNING_OCTOBROWSER.md](RUNNING_OCTOBROWSER.md) for details.

### 2. Create and start a profile via API

```bash
# Port from OctoBrowser
PORT=$(cat ~/.Octo\ Browser/local_port)
BASE="http://localhost:$PORT"

# Create profile
curl -s -X POST "$BASE/api/v2/profiles/quick" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Profile", "os": "win"}' | python3 -m json.tool

# Start profile (use uuid from response)
curl -s -X POST "$BASE/api/v2/profiles/<UUID>/start" \
  -H "Content-Type: application/json" \
  -d '{}'

# List profiles
curl -s -X POST "$BASE/api/v2/profiles/list" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool
```

See [LOCAL_API.md](LOCAL_API.md) for full API reference.

### 3. Shell helpers (optional)

```bash
source octo_commands.sh
octo_list
octo_create "My Profile"
octo_start <uuid>
octo_stop <uuid>
```

## Playwright

```bash
python3 octo_playwright.py
```

Requires a profile to be started (e.g. via API or GUI) with a debug port if you need CDP/Playwright connection.

## Local API overview

- **Base:** `http://localhost:{port}` — port in `~/.Octo Browser/local_port` (e.g. 58888)
- **Prefix:** `/api/v2/`
- **Key endpoints:** `POST /api/v2/profiles/list`, `POST /api/v2/profiles/quick`, `POST /api/v2/profiles/{uuid}/start`, `POST /api/v2/profiles/{uuid}/stop`

Full details: [LOCAL_API.md](LOCAL_API.md).

## Files summary

```
automation/
├── README.md                 # This index
├── LOCAL_API.md              # Local API reference
├── RUNNING_OCTOBROWSER.md    # VNC, root, sandbox
├── API_TIER_BYPASS.md        # Tier bypass (reverse engineering)
├── octo_commands.sh          # Shell helpers
├── octo_playwright.py        # Playwright script
└── octo_playwright_nb.py     # Playwright notebook version
```
