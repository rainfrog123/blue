# OctoBrowser Automation

Scripts for automating OctoBrowser via the local API and Cursor account workflow.

## Documentation

| Document | Purpose |
|----------|---------|
| [octo_local_api.md](octo_local_api.md) | Local API reference — endpoints, create/start/stop profiles |
| [octo_running.md](octo_running.md) | VNC, root, sandbox env vars, troubleshooting |

For reverse engineering, see [octo_reverse_engineering.md](octo_reverse_engineering.md).

## Quick Start

```bash
python cli.py launch
python cli.py status
python cli.py create "Test" --os win
python cli.py start UUID
```

See [octo_local_api.md](octo_local_api.md) for full API reference.

## Scripts

| File | Purpose |
|------|---------|
| `cursor_automation.py` | Main workflow — run cells sequentially to create Cursor accounts |
| `config.py` | Configuration, paths, settings — test with `python config.py` |
| `octo_helpers.py` | OctoBrowser API functions — test with `python octo_helpers.py` |
| `cursor_helpers.py` | Email/SMS/OTP helpers — test with `python cursor_helpers.py` |

## Cursor Account Automation

Modular automation with `# %%` cell markers for VS Code Interactive debugging.

### File Structure

```
auto/
├── config.py              # Paths & settings (test independently)
├── octo_helpers.py        # OctoBrowser API (test independently)
├── cursor_helpers.py     # Email/SMS helpers (test independently)
└── cursor_automation.py  # Main workflow (imports above)
```

### Usage in VS Code

1. Open `cursor_automation.py` in VS Code
2. Run cells with **Shift+Enter** (runs in Python Interactive window)
3. Each cell is independent — re-run any cell if it fails
4. Use `stop()` from another cell to break polling loops
5. Run `await debug_page()` anytime to screenshot current state

### Test Individual Modules

```bash
cd /allah/blue/web/auto/octo/auto

python config.py
python octo_helpers.py
python cursor_helpers.py
```

### Features

- Creates fresh OctoBrowser profile with randomized fingerprint
- Generates email using prefixes from `hyas_prefixes.txt`
- Polls Cloudflare Worker for email verification codes
- Uses HeroSMS for phone verification
- Captures Stripe checkout URL and session token
- Saves results to `docs/octo_session_tokens.txt`

### Dependencies

- `/allah/blue/web/auto/herosms/` — HeroSMS API wrapper
- `/allah/blue/web/auto/worker/hyas_prefixes.txt` — Email prefixes
- Cursor email worker at `https://cursor-email-worker.jar711red.workers.dev`

## Playwright

Connect Playwright to an OctoBrowser profile via CDP. Start profile with `debug_port: true`, then use `ws_endpoint` from the response. See [octo_local_api.md](octo_local_api.md) for the start endpoint. Example in `cursor_automation.py` uses `playwright.chromium.connect_over_cdp(ws_endpoint)`.

## Related

[octo_reverse_engineering.md](octo_reverse_engineering.md), [octo_bypasses.md](octo_bypasses.md), [octo_hid.md](octo_hid.md), [octo_ghidra_guides.md](octo_ghidra_guides.md)
