# OctoBrowser Tools

Tools for OctoBrowser automation and reverse engineering.

## Quick Start

```bash
python cli.py launch
python cli.py status
```

See [octo_running.md](octo_running.md) for VNC/root setup. See [octo_local_api.md](octo_local_api.md) for API.

## Project Structure

```
octo/
├── cli.py                 # Launch, setup, profiles
├── auto/                  # cursor_automation, config, helpers
├── docs/                  # All documentation
├── reverse_engineering/   # api_tier_bypass, hid, ssl, storage_decryption
└── clash/                 # Proxy management
```

## Docs Index

| Doc | Purpose |
|-----|---------|
| [octo_local_api.md](octo_local_api.md) | Local API reference |
| [octo_running.md](octo_running.md) | VNC, root, sandbox |
| [octo_automation.md](octo_automation.md) | Cursor automation |
| [octo_fingerprint_research.md](octo_fingerprint_research.md) | Fingerprint bypass |
| [octo_reverse_engineering.md](octo_reverse_engineering.md) | RE overview + architecture |

## RE Modules

| Doc | Purpose |
|-----|---------|
| [octo_bypasses.md](octo_bypasses.md) | API tier + SSL bypass |
| [octo_hid.md](octo_hid.md) | HID fingerprinting |
| [octo_ghidra_guides.md](octo_ghidra_guides.md) | Ghidra: HID + decryption |
