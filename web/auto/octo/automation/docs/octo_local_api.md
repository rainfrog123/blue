# OctoBrowser Local API Reference

Local API for controlling OctoBrowser when running on your machine.

**Base URL:** `http://localhost:59999`  
**Authentication:** None required (local only)  
**Requires:** OctoBrowser desktop app running

---

## Profile Management

### List Active Profiles
Get all currently running profiles on your device.

```
GET /api/profiles/active
```

**Response:**
```json
[
  {
    "uuid": "2bbfd1dbaf3349cf979787f15a9e413d",
    "state": "STARTED",
    "headless": true,
    "start_time": 1724173918,
    "ws_endpoint": "ws://127.0.0.1:55834/devtools/browser/a26c9612-6479-43f1-87ef-34590321a99a",
    "debug_port": "55834",
    "one_time": false,
    "browser_pid": 26616
  }
]
```

---

### Start Profile
Launch a profile for automation.

```
POST /api/profiles/start
```

**Request Body:**
```json
{
    "uuid": "PROFILE_UUID",
    "headless": false,
    "debug_port": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `uuid` | string | Profile UUID (required) |
| `headless` | boolean | Run without visible window |
| `debug_port` | boolean | Return debug port for automation |

**Response:**
```json
{
    "ws_endpoint": "ws://127.0.0.1:55834/devtools/browser/...",
    "debug_port": "55834"
}
```

**Usage with Playwright:**
```python
browser = await playwright.chromium.connect_over_cdp(ws_endpoint)
```

---

### Stop Profile
Stop a running profile gracefully.

```
POST /api/profiles/stop
```

**Request Body:**
```json
{
    "uuid": "PROFILE_UUID"
}
```

**Response:**
```json
{
    "msg": "Profile stopped"
}
```

---

### Force Stop Profile
Force stop a profile (requires Octo Browser 1.7+).

```
POST /api/profiles/force_stop
```

**Request Body:**
```json
{
    "uuid": "PROFILE_UUID"
}
```

**Response:**
```json
{
    "msg": "Profile stopped successfully"
}
```

---

### Delete Profile Password
Clear the password from a profile.

```
DELETE /api/profiles/password
```

**Request Body:**
```json
{
    "uuid": "PROFILE_UUID",
    "password": "current_password"
}
```

**Response:**
```json
{
    "msg": "Profile password has been cleared"
}
```

---

## Client Management

### Get Client Version
Check current and latest available browser versions.

```
GET /api/update
```

**Response:**
```json
{
    "current": "1.8.2",
    "latest": "1.8.3",
    "update_required": false
}
```

---

### Update Client
Trigger an update to the latest version.

```
POST /api/update
```

**Response:**
```json
{
    "msg": "update to 1.8.3 triggered successfully"
}
```

---

## V2 API Endpoints (Local)

These endpoints mirror the cloud API but work locally without authentication.

### Check API Status
Verify if OctoBrowser API is running.

```
GET /api/v2/client/themes
```

**Response:**
```json
{
    "success": true,
    "data": [...]
}
```

---

### List All Profiles
Get all profiles (running and stopped).

```
POST /api/v2/profiles/list
```

**Request Body:**
```json
{}
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
                "status": 0,
                "tags": [],
                "proxy": null,
                "last_active": "2024-01-01T00:00:00"
            }
        ]
    }
}
```

| Status | Meaning |
|--------|---------|
| 0 | Stopped |
| 6 | Running |

---

### Get Profile Details
Get full details for a specific profile.

```
GET /api/v2/profiles/{uuid}/view
```

**Response:**
```json
{
    "success": true,
    "data": {
        "uuid": "...",
        "title": "Profile Name",
        "fingerprint": {...},
        "proxy": {...},
        "tags": [],
        "status": 0
    }
}
```

---

### Get Fingerprint Boilerplate
Generate a random fingerprint template.

```
POST /api/v2/profiles/boilerplate/quick
```

**Request Body:**
```json
{
    "os": "mac",
    "os_arch": "arm",
    "count": 1
}
```

| Field | Type | Values |
|-------|------|--------|
| `os` | string | `mac`, `win`, `linux` |
| `os_arch` | string | `arm`, `x86` |
| `count` | integer | Number of fingerprints to generate |

**Response:**
```json
{
    "success": true,
    "data": {
        "boilerplates": [
            {
                "fp": {
                    "os": "mac",
                    "os_arch": "arm",
                    "user_agent": "Mozilla/5.0...",
                    "screen": "1470x956 (Retina)",
                    "languages": {"type": "ip", "data": null},
                    "timezone": {"type": "ip", "data": null},
                    "geolocation": {"type": "ip", "data": null},
                    "cpu": 8,
                    "ram": 16,
                    "renderer": "Apple M3",
                    "webrtc": {"type": "ip", "data": null},
                    "dns": null,
                    "fonts": [...],
                    "media_devices": {...},
                    "noise": {...}
                },
                "name": "auto-generated-name",
                "logo": "55e228c7227946b3889f370b54be26c1",
                "tags": [],
                "proxies": [],
                "bookmarks": [],
                "start_pages": [],
                "launch_args": [],
                "description": "",
                "local_cache": false,
                "storage_options": {...}
            }
        ]
    }
}
```

---

### Create Profile
Create a new profile with custom settings.

```
POST /api/v2/profiles
```

**Request Body (no proxy):**
```json
{
    "title": "My Custom Profile",
    "name": "My Custom Profile",
    "description": "",
    "start_pages": [],
    "bookmarks": [],
    "launch_args": [],
    "logo": "55e228c7227946b3889f370b54be26c1",
    "tags": [],
    "fp": {
        "os": "win",
        "os_arch": "x86",
        "user_agent": "Mozilla/5.0...",
        "screen": "1920x1080",
        "languages": {"type": "ip", "data": null},
        "timezone": {"type": "ip", "data": null},
        "geolocation": {"type": "ip", "data": null},
        "cpu": 8,
        "ram": 16,
        "renderer": "NVIDIA GeForce RTX 4090",
        "webrtc": {"type": "ip", "data": null},
        "dns": "",
        "fonts": [...],
        "media_devices": {...},
        "noise": {"webgl": true, "canvas": true, "audio": true, "client_rects": true}
    },
    "proxy": {"type": "direct"},
    "proxies": [],
    "local_cache": false,
    "storage_options": {
        "cookies": true,
        "passwords": true,
        "extensions": true,
        "localstorage": false,
        "history": false,
        "bookmarks": true,
        "serviceworkers": false
    }
}
```

**Request Body (with proxy):**
```json
{
    "title": "Profile-With-Proxy",
    "name": "Profile-With-Proxy",
    "proxy": {
        "type": "new",
        "data": {
            "type": "http",
            "ip": "proxy.example.com",
            "port": 8080,
            "login": "username",
            "password": "password"
        }
    },
    ...
}
```

**Important Notes:**
- `name` field becomes the displayed `title`
- `fp.dns` must be `""` (empty string), not `null`
- Both `proxy` (dict) and `proxies` (list) are required
- `logo` must be 32+ characters or omitted
- For proxy: use `{"type": "direct"}` for no proxy, `{"type": "new", "data": {...}}` with proxy

**Response:**
```json
{
    "success": true,
    "data": {
        "uuid": "654f40d97856458bb844fa24fde48b12",
        "title": "My Custom Profile",
        "status": 0
    }
}
```

---

### Delete Profiles
Delete one or more profiles by UUID.

```
POST /api/v2/profiles/delete
```

**Request Body:**
```json
{
    "uuids": ["uuid1", "uuid2"]
}
```

**Response:**
```json
{
    "success": true,
    "data": ""
}
```

---

## Quick Create Profile (Simplified)

For simple profile creation without custom fingerprints:

```
POST /api/v2/profiles/quick
```

**Request Body:**
```json
{
    "title": "Quick Profile",
    "os": "mac"
}
```

**Note:** This endpoint auto-generates a title and doesn't support custom titles reliably. Use the boilerplate approach for custom titles.

---

## Proxy Configuration

### Profile Proxy Types (for profile creation)

When creating a profile, the `proxy` field accepts these types:

| Type | Description | Format |
|------|-------------|--------|
| `direct` | No proxy | `{"type": "direct"}` |
| `new` | Create new proxy | `{"type": "new", "data": {...}}` |
| `list` | Use existing proxy | `{"type": "list", "data": "proxy_uuid"}` |

### Creating Profile with New Proxy

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

**Important:** Use `"ip"` for the hostname field, not `"host"`.

### Proxy Protocol Types (inside `data`)

| Type | Description |
|------|-------------|
| `http` | HTTP proxy |
| `https` | HTTPS proxy |
| `socks4` | SOCKS4 proxy |
| `socks5` | SOCKS5 proxy |

### Full Example: Profile with Residential Proxy

```python
import requests

API = "http://localhost:59999"

# Get boilerplate
resp = requests.post(
    f"{API}/api/v2/profiles/boilerplate/quick",
    json={"os": "win", "os_arch": "x86", "count": 1}
)
bp = resp.json()["data"]["boilerplates"][0]
fp = bp["fp"]
fp["dns"] = "" if fp.get("dns") is None else fp["dns"]

# Create profile with proxy
payload = {
    "title": "Profile-With-Proxy",
    "name": "Profile-With-Proxy",
    "description": "",
    "start_pages": [],
    "bookmarks": [],
    "launch_args": [],
    "logo": bp.get("logo", ""),
    "tags": [],
    "fp": fp,
    "proxy": {
        "type": "new",
        "data": {
            "type": "http",
            "ip": "de.decodo.com",
            "port": 30209,
            "login": "user-session123",
            "password": "secretpass"
        }
    },
    "proxies": [],
    "local_cache": False,
    "storage_options": bp.get("storage_options", {}),
}

resp = requests.post(f"{API}/api/v2/profiles", json=payload)
print(resp.json())
```

### Proxy Response (from profile view)

After creation, the proxy is stored with additional metadata:

```json
{
    "uuid": "2e3172b83ffa4bc881e082aa26800ee3",
    "temp": true,
    "type": "http",
    "ip": "de.decodo.com",
    "port": 30209,
    "login": "user-session123",
    "password": "secretpass",
    "country": null,
    "external_ip": null,
    "compound_id": "http://user-session123:secretpass@de.decodo.com:30209"
}
```

---

## Fingerprint Options

### WebRTC Types
```json
{"type": "ip", "data": null}           // Use proxy IP
{"type": "real", "data": null}         // Use real IP
{"type": "disable_non_proxied_udp"}    // Disable non-proxied UDP
```

### Language/Timezone/Geolocation Types
```json
{"type": "ip", "data": null}           // Auto-detect from IP
{"type": "manual", "data": "value"}    // Manual setting
```

### Noise Options
```json
{
    "webgl": false,
    "canvas": false,
    "audio": false,
    "client_rects": false
}
```

---

## Running Headless

### Linux
```bash
OCTO_HEADLESS=1 ./OctoBrowser.AppImage
```

### Windows (PowerShell)
```powershell
$env:OCTO_HEADLESS = "1"; start 'C:\Program Files\Octo Browser\Octo Browser.exe'
```

### macOS
```bash
OCTO_HEADLESS=1 open -a "Octo Browser"
```

---

## Error Codes

| Code | Description |
|------|-------------|
| `profiles.maximum_saved_error` | Profile limit reached |
| `profiles.stop_error` | Failed to stop profile |
| `validation_error` | Invalid request body |

---

## Python Example

```python
import requests

API = "http://localhost:59999"

# Check if running
def is_running():
    try:
        resp = requests.get(f"{API}/api/v2/client/themes", timeout=3)
        return resp.json().get("success", False)
    except:
        return False

# List profiles
def list_profiles():
    resp = requests.post(f"{API}/api/v2/profiles/list", json={})
    return resp.json()["data"]["profiles"]

# Start profile
def start_profile(uuid):
    resp = requests.post(
        f"{API}/api/profiles/start",
        json={"uuid": uuid, "debug_port": True}
    )
    return resp.json()["ws_endpoint"]

# Stop profile
def stop_profile(uuid):
    requests.post(f"{API}/api/profiles/stop", json={"uuid": uuid})
```

---

## See Also

- [Cloud API Documentation](https://documenter.getpostman.com/view/1801428/UVC6i6eA)
- [Official Docs](https://docs.octobrowser.net/en/api/start-api/)
