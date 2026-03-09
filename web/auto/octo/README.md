# OctoBrowser Tools

Tools and documentation for OctoBrowser automation and reverse engineering.

## Project Structure

```
octo/
├── README.md                    # This file - project overview
├── docs/                        # Documentation
│   ├── LOCAL_API.md             # Local API reference
│   └── RUNNING_OCTOBROWSER.md   # VNC, root, sandbox setup
├── automation/                  # Browser automation scripts
│   ├── README.md                # Automation documentation
│   ├── cursor_automation.py     # Cursor account automation
│   ├── playwright_*.py          # Playwright automation scripts
│   └── octo_shell_commands.sh   # Shell helpers
├── reverse_engineering/         # Reverse engineering tools
│   ├── README.md                # RE overview
│   ├── api_tier_bypass/         # API tier restriction bypass
│   ├── hid/                     # Hardware ID fingerprinting
│   ├── ssl/                     # SSL/TLS certificate pinning bypass
│   └── storage_decryption/      # Local storage encryption
├── clash/                       # Proxy management
│   ├── clash_proxy_manager.py   # Proxy manager
│   └── ip_quality_score_checker.py
├── start_octo.sh                # Start OctoBrowser (VNC/root)
└── octo_environment_setup.sh    # Initial setup script
```

## Quick Start

### 1. Run OctoBrowser

```bash
./start_octo.sh
```

Or manually:
```bash
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" \
  QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" \
  /opt/octobrowser/OctoBrowser.AppImage --no-sandbox
```

See [docs/RUNNING_OCTOBROWSER.md](docs/RUNNING_OCTOBROWSER.md) for details.

### 2. Use the Local API

```bash
# Test API
curl -s http://localhost:59999/api/v2/client/themes

# Create profile
curl -s -X POST "http://localhost:59999/api/v2/profiles/quick" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Profile", "os": "win"}'
```

See [docs/LOCAL_API.md](docs/LOCAL_API.md) for full API reference.

### 3. Automation

```bash
cd automation
python3 cursor_automation.py
```

See [automation/README.md](automation/README.md) for automation documentation.

### 4. Reverse Engineering

```bash
cd reverse_engineering
# See individual module READMEs for specific tools
```

| Module | Purpose |
|--------|---------|
| [api_tier_bypass/](reverse_engineering/api_tier_bypass/) | Bypass API subscription restrictions |
| [hid/](reverse_engineering/hid/) | HID fingerprinting and spoofing |
| [ssl/](reverse_engineering/ssl/) | SSL pinning bypass |
| [storage_decryption/](reverse_engineering/storage_decryption/) | Decrypt local storage |

## OctoBrowser Info

### Architecture
- **Type**: PyInstaller AppImage (Linux)
- **Python**: 3.12
- **Browser Engine**: QtWebEngine (Chromium 134)
- **SSL Library**: NSS (libnss3.so) + OpenSSL

### Endpoints

| Domain | Purpose |
|--------|---------|
| `app.octobrowser.net` | Main API (Cloudflare) |
| `app01.octobrowser.net` | Secondary API (AWS) |
| `app.obiwankenode.com` | Internal API (AWS) |
| `localhost:59999` | Local backend (uvicorn) |

### Data Locations

| Path | Purpose |
|------|---------|
| `~/.Octo Browser/` | Main data directory |
| `~/.Octo Browser/local.data` | Session storage (encrypted) |
| `~/.Octo Browser/localpersist.data` | Persistent storage (encrypted) |
| `~/.Octo Browser/local_port` | Local API port |
