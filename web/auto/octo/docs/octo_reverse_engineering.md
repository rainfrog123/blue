# OctoBrowser Reverse Engineering

Tools and documentation for reverse engineering OctoBrowser internals.

## Modules

| Doc | Purpose |
|-----|---------|
| [octo_bypasses.md](octo_bypasses.md) | API tier bypass + SSL pinning bypass |
| [octo_hid.md](octo_hid.md) | Hardware ID (HID) fingerprinting analysis and spoofing |
| [octo_ghidra_guides.md](octo_ghidra_guides.md) | Ghidra tutorials: HID discovery + storage decryption |

## Reference: Architecture & Data

| Item | Value |
|------|-------|
| Type | PyInstaller AppImage (Linux) |
| Python | 3.12 |
| Browser Engine | QtWebEngine (Chromium 134) |
| SSL Library | NSS (libnss3.so) + OpenSSL |

| Domain | Purpose |
|--------|---------|
| `app.octobrowser.net` | Main API (Cloudflare) |
| `app01.octobrowser.net` | Secondary API (AWS) |
| `app.obiwankenode.com` | Internal API (AWS) |
| `localhost:59999` | Local backend (uvicorn) |

| Path | Purpose |
|------|---------|
| `~/.Octo Browser/` | Main data directory |
| `~/.Octo Browser/local_port` | Local API port |
| `~/.Octo Browser/local.data` | Session storage (encrypted) |
| `~/.Octo Browser/localpersist.data` | Persistent storage (encrypted) |
| `~/.Octo Browser/logs/debug.log` | Debug logs |
| `/tmp/_MEI*` | Runtime extraction (PyInstaller) |

## Key Findings

| Area | Discovery |
|------|-----------|
| **HID** | Machine ID from `/etc/machine-id` used for encryption key derivation |
| **Encryption** | Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation |
| **Secret** | `"TeNtAcLeShErE___"` used in key derivation |
| **API Tier** | Feature checks in `octo/fastapi/dependencies.pyc` |

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
