# OctoBrowser Automation

Scripts for automating OctoBrowser using Playwright and other tools.

## Files

| File | Purpose |
|------|---------|
| `octo_playwright.py` | Playwright automation script |
| `octo_playwright_nb.py` | Notebook-friendly version |
| `octo_commands.sh` | Common shell commands |

## Usage

### Playwright

```bash
python3 octo_playwright.py
```

### Local API

OctoBrowser runs a local API server:

- **Port**: 58888
- **Server**: uvicorn (Python)
- **Start**: `/new/app/start?v={version}&client_uuid={uuid}`

```bash
# Check if running
curl http://localhost:58888/
```
