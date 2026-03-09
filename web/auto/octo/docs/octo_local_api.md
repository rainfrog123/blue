# OctoBrowser Local API

**Base URL:** `http://localhost:59999`  
**Auth:** None (local only)

---

## Quick Reference

| Action | Method | Endpoint |
|--------|--------|----------|
| Check status | GET | `/api/v2/client/themes` |
| List profiles | POST | `/api/v2/profiles/list` |
| Get profile | GET | `/api/v2/profiles/{uuid}` |
| Create profile | POST | `/api/v2/profiles` |
| Delete profiles | POST | `/api/v2/profiles/delete` |
| Clone profile | POST | `/api/v2/profiles/{uuid}/clone` |
| Start profile | POST | `/api/profiles/start` |
| Stop profile | POST | `/api/profiles/stop` |
| Active profiles | GET | `/api/profiles/active` |
| Get boilerplate | POST | `/api/v2/profiles/boilerplate/quick` |
| Version | GET | `/api/update` |

---

## Profiles

### List Profiles

```bash
curl -X POST http://localhost:59999/api/v2/profiles/list \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "profiles": [
      {
        "uuid": "abc123...",
        "title": "My Profile",
        "os": "win",
        "status": 0,
        "tags": []
      }
    ]
  }
}
```

Status: `0`=stopped, `6`=running

---

### Start Profile

```bash
curl -X POST http://localhost:59999/api/profiles/start \
  -H "Content-Type: application/json" \
  -d '{"uuid": "PROFILE_UUID", "debug_port": true}'
```

**Response:**
```json
{
  "state": "STARTED",
  "ws_endpoint": "ws://127.0.0.1:55834/devtools/browser/...",
  "debug_port": "55834",
  "browser_pid": 12345
}
```

Use `ws_endpoint` with Playwright:
```python
browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
```

---

### Stop Profile

```bash
curl -X POST http://localhost:59999/api/profiles/stop \
  -H "Content-Type: application/json" \
  -d '{"uuid": "PROFILE_UUID"}'
```

---

### Active Profiles

```bash
curl http://localhost:59999/api/profiles/active
```

Returns list of running profiles with their `ws_endpoint` and `debug_port`.

---

### Get Profile Details

```bash
curl http://localhost:59999/api/v2/profiles/{uuid}
```

---

### Delete Profiles

```bash
curl -X POST http://localhost:59999/api/v2/profiles/delete \
  -H "Content-Type: application/json" \
  -d '{"uuids": ["uuid1", "uuid2"]}'
```

---

### Clone Profile

```bash
curl -X POST http://localhost:59999/api/v2/profiles/{uuid}/clone \
  -H "Content-Type: application/json" \
  -d '{"amount": 1}'
```

---

## Create Profile

### Get Boilerplate First

```bash
curl -X POST http://localhost:59999/api/v2/profiles/boilerplate/quick \
  -H "Content-Type: application/json" \
  -d '{"os": "win", "os_arch": "x86", "count": 1}'
```

OS options: `win`, `mac`, `android`  
Arch: `x86` (Windows), `arm` (Mac/Android)

### Create with Boilerplate

```bash
curl -X POST http://localhost:59999/api/v2/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Profile",
    "name": "My Profile",
    "description": "",
    "start_pages": [],
    "bookmarks": [],
    "launch_args": [],
    "logo": "...",
    "tags": [],
    "fp": { ... },
    "proxy": {"type": "direct"},
    "proxies": [],
    "local_cache": false,
    "storage_options": { ... }
  }'
```

**Required fixes:**
- `fp.dns` must be `""` not `null`
- Android: `storage_options.extensions = false`

---

## Proxy Configuration

### No Proxy
```json
{"proxy": {"type": "direct"}}
```

### New Proxy
```json
{
  "proxy": {
    "type": "new",
    "data": {
      "type": "http",
      "ip": "proxy.example.com",
      "port": 8080,
      "login": "username",
      "password": "password"
    }
  }
}
```

**Important:** Use `"ip"` for hostname, not `"host"`.

Proxy types: `http`, `https`, `socks4`, `socks5`

---

## Fingerprint Options

### Noise (randomizes hashes)
```json
{
  "fp": {
    "noise": {
      "webgl": true,
      "canvas": true,
      "audio": true,
      "client_rects": true
    }
  }
}
```

### WebRTC
```json
{"webrtc": {"type": "ip", "data": null}}
{"webrtc": {"type": "disable_non_proxied_udp", "data": null}}
{"webrtc": {"type": "real", "data": null}}
```

### Auto from IP
```json
{"languages": {"type": "ip", "data": null}}
{"timezone": {"type": "ip", "data": null}}
{"geolocation": {"type": "ip", "data": null}}
```

---

## Python Example

```python
import requests

API = "http://localhost:59999"

def list_profiles():
    resp = requests.post(f"{API}/api/v2/profiles/list", json={})
    return resp.json()["data"]["profiles"]

def start_profile(uuid):
    resp = requests.post(
        f"{API}/api/profiles/start",
        json={"uuid": uuid, "debug_port": True}
    )
    return resp.json()["ws_endpoint"]

def stop_profile(uuid):
    requests.post(f"{API}/api/profiles/stop", json={"uuid": uuid})
```

---

## CLI Usage

Use `cli.py` for command-line access:

```bash
python cli.py status                    # Check status
python cli.py list                      # List profiles
python cli.py create "Test" --os win    # Create profile
python cli.py create "Test" --proxy URL # With proxy
python cli.py start UUID                # Start profile
python cli.py stop UUID                 # Stop profile
python cli.py ip UUID                   # Check IP
python cli.py test UUID                 # Test on PixelScan
```
