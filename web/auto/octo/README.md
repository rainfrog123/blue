# OctoBrowser Reverse Engineering

Tools and documentation for reverse engineering OctoBrowser.

## Project Structure

```
octo/
├── README.md              # This file - project overview
├── ssl_pinning/           # SSL/TLS certificate pinning bypass
│   ├── README.md          # SSL bypass documentation
│   ├── ghidra_*.py        # Ghidra analysis and patching scripts
│   ├── frida_*.js         # Frida hooking scripts
│   ├── patch_*.py         # Binary patching scripts
│   └── *.sh               # Launcher scripts
├── hid/                   # Hardware ID fingerprinting analysis
│   ├── README.md          # HID documentation
│   ├── ghidra_*.py        # Ghidra analysis scripts
│   └── decrypt_*.py       # Storage decryption tools
├── automation/            # Browser automation scripts
│   ├── octo_playwright.py # Playwright automation
│   └── octo_commands.sh   # Common commands
└── setup_octo.sh          # Initial setup script
```

## Quick Start

### SSL Pinning Bypass

```bash
# Patch and run OctoBrowser with SSL interception
cd ssl_pinning
./patch_and_run_octo.sh
```

See [ssl_pinning/README.md](ssl_pinning/README.md) for full documentation.

### HID Analysis

```bash
# Analyze HID fingerprinting
cd hid
python3 ghidra_hid_analyzer.py

# View current machine HID
cat /etc/machine-id
```

See [hid/README.md](hid/README.md) for full documentation.

## Tools Reference

### Ghidra

```bash
# Location
/opt/ghidra  # symlink to /opt/tools/ghidra_11.3.1_PUBLIC

# GUI mode
DISPLAY=:1 /opt/ghidra/ghidraRun

# Headless analysis
/opt/ghidra/support/analyzeHeadless <project_dir> <project_name> -import <binary>
```

### Mitmproxy

```bash
# Basic proxy
mitmdump -p 8080

# Save traffic
mitmdump -p 8080 -w traffic.flow

# Read traffic
mitmdump -r traffic.flow --flow-detail 3

# Filter domains
mitmdump -r traffic.flow "~d octobrowser"
```

### Frida

```bash
# List processes
frida-ps

# Trace functions
frida-trace -i "open*" <pid>

# Inject script
frida -p <pid> -l script.js
```

### Tshark

```bash
# Capture TLS SNI
tshark -i any -Y 'tls.handshake.extensions_server_name' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

## OctoBrowser Info

### Architecture
- **Type**: PyInstaller AppImage (Linux)
- **Python**: 3.12
- **Browser Engine**: QtWebEngine (Chromium 134)
- **SSL Library**: NSS (libnss3.so) + OpenSSL

### Discovered Endpoints

| Domain | Purpose |
|--------|---------|
| `app.octobrowser.net` | Main API (Cloudflare) |
| `app01.octobrowser.net` | Secondary API (AWS) |
| `app.obiwankenode.com` | Internal API (AWS) |
| `localhost:56933` | Local backend (uvicorn) |

### Data Locations

| Path | Purpose |
|------|---------|
| `~/.Octo Browser/` | Main data directory |
| `~/.Octo Browser/local.data` | Session storage (encrypted) |
| `~/.Octo Browser/localpersist.data` | Persistent storage (encrypted) |
| `/tmp/_MEI*` | Runtime extraction directory |

## Extracted AppImage

```bash
# Extract for analysis
cd /tmp
python3 pyinstxtractor.py /home/vncuser/Downloads/OctoBrowser.AppImage

# Key files
/tmp/OctoBrowser.AppImage_extracted/
├── libnss3.so              # NSS SSL library
├── libssl.so.3             # OpenSSL
├── libcrypto.so.3          # OpenSSL crypto
├── libQt6WebEngineCore.so.6 # Qt browser engine (193MB)
├── PYZ.pyz_extracted/      # Python bytecode
│   ├── config.pyc          # Configuration with HID logic
│   └── octo/               # Main application code
└── main.pyc                # Entry point
```

## Notes

- OctoBrowser has anti-debugging protections
- Frida causes crashes due to integrity checks
- Binary patching before execution is more reliable
- HID is used for both encryption and license binding
