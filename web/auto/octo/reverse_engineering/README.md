# OctoBrowser Reverse Engineering

Tools and documentation for reverse engineering OctoBrowser internals.

## Modules

| Directory | Purpose |
|-----------|---------|
| [api_tier_bypass/](api_tier_bypass/) | Bypassing API subscription tier restrictions |
| [hid/](hid/) | Hardware ID (HID) fingerprinting analysis and spoofing |
| [ssl/](ssl/) | SSL/TLS certificate pinning bypass |
| [storage_decryption/](storage_decryption/) | Local storage encryption analysis and decryption |

## Overview

OctoBrowser is a PyInstaller-packed Python application with:
- **Python**: 3.12
- **Browser Engine**: QtWebEngine (Chromium 134)
- **SSL Library**: NSS (libnss3.so) + OpenSSL

### Key Findings

| Area | Discovery |
|------|-----------|
| **HID** | Machine ID from `/etc/machine-id` used for encryption key derivation |
| **Encryption** | Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation |
| **Secret** | `"TeNtAcLeShErE___"` used in key derivation |
| **API Tier** | Feature checks in `octo/fastapi/dependencies.pyc` |

### Data Locations

| Path | Purpose |
|------|---------|
| `~/.Octo Browser/` | Main data directory |
| `~/.Octo Browser/local.data` | Session storage (encrypted) |
| `~/.Octo Browser/localpersist.data` | Persistent storage (encrypted) |
| `/tmp/_MEI*` | Runtime extraction directory |

### Server Endpoints

| Domain | Purpose |
|--------|---------|
| `app.octobrowser.net` | Main API (Cloudflare) |
| `app01.octobrowser.net` | Secondary API (AWS) |
| `app.obiwankenode.com` | Internal API (AWS) |
| `localhost:56933` | Local backend (uvicorn) |

## Tools

| Tool | Location | Purpose |
|------|----------|---------|
| Ghidra | `/opt/ghidra` | Binary analysis |
| pycdc | pip | Python bytecode decompilation |
| mitmproxy | pip | HTTP interception |
| Frida | pip | Runtime hooking |

### Ghidra

```bash
# GUI mode
DISPLAY=:1 /opt/ghidra/ghidraRun

# Headless analysis
/opt/ghidra/support/analyzeHeadless <project_dir> <project_name> -import <binary>
```

### AppImage Extraction

```bash
cd /tmp
python3 pyinstxtractor.py /home/vncuser/Downloads/OctoBrowser.AppImage

# Key files in extracted directory:
# PYZ.pyz_extracted/  - Python bytecode
# libnss3.so          - NSS SSL library
# libssl.so.3         - OpenSSL
```

## Notes

- OctoBrowser has anti-debugging protections
- Frida may cause crashes due to integrity checks
- Binary patching before execution is more reliable
- HID is used for both encryption and license binding
