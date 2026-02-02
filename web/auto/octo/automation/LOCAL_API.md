# OctoBrowser Local API Reference

Documentation for the OctoBrowser local HTTP API used for automation and profile management.

## Overview

- **Base URL**: `http://localhost:{port}` — port is stored in `~/.Octo Browser/local_port` (default 58888)
- **API prefix**: `/api/v2/`
- **Content-Type**: `application/json` for request/response bodies
- **Server**: FastAPI (uvicorn) inside OctoBrowser process

OctoBrowser must be running for the API to be available.

## Getting the Port

```bash
# Read port from OctoBrowser storage
cat ~/.Octo\ Browser/local_port
# Example output: 58888
```

## Quick Reference

| Action | Method | Endpoint | Body |
|--------|--------|----------|------|
| List profiles | POST | `/api/v2/profiles/list` | `{}` |
| Create profile (quick) | POST | `/api/v2/profiles/quick` | `{"title": "...", "os": "win"}` |
| Start profile | POST | `/api/v2/profiles/{uuid}/start` | `{}` |
| Stop profile | POST | `/api/v2/profiles/{uuid}/stop` | `{}` |
| Get profile view | GET | `/api/v2/profiles/{uuid}/view` | — |
| Client themes | GET | `/api/v2/client/themes` | — |

## Endpoints

### Client

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/client/themes` | GET | Get UI theme (system_theme, user_theme) |

**Example:**
```bash
curl -s http://localhost:58888/api/v2/client/themes
# {"success":true,"data":{"system_theme":"light","user_theme":null},"error":null,"msg":null}
```

### Profiles

#### List profiles

```http
POST /api/v2/profiles/list
Content-Type: application/json

{}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "profiles": [
      {
        "uuid": "61fe4cf012f446deb14443ca0d9d9ebb",
        "title": "Quick tearful-chicken",
        "description": "",
        "image": "...",
        "tags": [],
        "proxy": null,
        "status": 0,
        "current_user": null,
        "current_hid": null,
        "current_cid": null,
        "last_active": null,
        "has_user_password": false,
        "os": "win",
        "os_arch": "x86",
        "os_version": "10",
        "created_at": "2026-02-02T19:18:16",
        "run_time": 0.0,
        "starts_count": 0,
        "size_bytes": 0,
        "cookies_count": 0,
        "real_ip": null
      }
    ],
    "total": 1
  },
  "error": null,
  "msg": null,
  "reason": null
}
```

**Profile status values:** `0` = stopped, `1` = starting/syncing, `6` = running (or similar; check response).

#### Create profile (quick)

Creates a profile with a random fingerprint and optional title.

```http
POST /api/v2/profiles/quick
Content-Type: application/json

{
  "title": "My Profile",
  "os": "win"
}
```

**Parameters:**
- `title` (string, optional): Display name. If omitted, a random name like "Quick tearful-chicken" is used.
- `os` (string, required): `"win"` | `"mac"` | `"android"` | `"template"`

**Response:**
```json
{
  "success": true,
  "data": {
    "uuid": "61fe4cf012f446deb14443ca0d9d9ebb",
    "title": "Quick tearful-chicken",
    "image": "...",
    "tags": [],
    "proxy": null,
    "status": 0,
    "created_at": "2026-02-02T19:18:16",
    "has_user_password": false,
    "run_time": 0.0,
    "starts_count": 0,
    "cookies_count": 0,
    "size_bytes": 0
  },
  "error": null,
  "msg": null
}
```

**Example:**
```bash
curl -s -X POST http://localhost:58888/api/v2/profiles/quick \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Profile", "os": "win"}'
```

#### Get profile boilerplate

Returns a template for creating a profile with custom fingerprint (used for full create, not quick).

```http
POST /api/v2/profiles/boilerplate
Content-Type: application/json

{
  "os": "win"
}
```

**Parameters:** `os`: `"win"` | `"mac"` | `"android"` | `"template"`

#### Start profile

```http
POST /api/v2/profiles/{profile_uuid}/start
Content-Type: application/json

{}
```

**Response:** `{"success": true, "data": null, "error": null, "msg": null, "reason": null}`

**Example:**
```bash
curl -s -X POST "http://localhost:58888/api/v2/profiles/61fe4cf012f446deb14443ca0d9d9ebb/start" \
  -H "Content-Type: application/json" \
  -d '{}'
```

#### Stop profile

```http
POST /api/v2/profiles/{profile_uuid}/stop
Content-Type: application/json

{}
```

#### Get profile (view)

```http
GET /api/v2/profiles/{profile_uuid}/view
```

Returns full profile details including `encrypted_password`, `proxy_view`, etc.

### Other profile endpoints (from bytecode)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/profiles/boilerplate` | POST | Get create template (body: `{"os": "win"}`) |
| `/api/v2/profiles/boilerplate/import` | POST | Import from boilerplate |
| `/api/v2/profiles/boilerplate/quick` | POST | Quick create from boilerplate |
| `/api/v2/profiles/{uuid}/clone` | POST | Clone profile |
| `/api/v2/profiles/{uuid}/quick` | POST | Quick action |
| `/api/v2/profiles/delete` | POST | Delete profile(es) |
| `/api/v2/profiles/import` | POST | Import profiles |
| `/api/v2/profiles/export` | POST | Export profiles |
| `/api/v2/profiles/export_paginate` | POST | Paginated export |
| `/api/v2/profiles/tags` | * | Profile tags |
| `/api/v2/profiles/manage_tags` | * | Manage tags |
| `/api/v2/profiles/proxy` | POST | Set proxy (mass) |
| `/api/v2/profiles/password` | * | Password |
| `/api/v2/profiles/batch` | POST | Batch operation |
| `/api/v2/profiles/trash_bin` | * | Trash bin |
| `/api/v2/profiles/trash_bin/put_back` | * | Restore from trash |
| `/api/v2/profiles/set_pin_tag` | * | Pin tag |
| `/api/v2/profiles/set_query` | POST | Set list query |
| `/api/v2/profiles/save_exported` | POST | Save exported |
| `/api/v2/transfer_profiles` | * | Transfer |
| `/api/v2/export_profiles` | * | Export |
| `/api/v2/set_proxy_mass` | * | Mass proxy |

Exact request/response schemas for these can be inferred from the app or from decompiled `octo/fastapi/routers/profiles/schemas.pyc`.

## Response format

All JSON responses follow this shape when successful:

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "msg": null,
  "reason": null
}
```

On error (e.g. validation):

```json
{
  "detail": [
    {
      "loc": ["body", "os"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Or server error:

```json
{
  "success": false,
  "data": null,
  "error": {
    "message": "Something went wrong",
    "validation_error": null,
    "code": null,
    "code_id": null
  },
  "msg": null,
  "reason": null
}
```

## Web UI

The same server serves the OctoBrowser web UI:

- **App entry**: `http://localhost:58888/new/app/start` (or `/new/app/start?v=...&client_uuid=...`)
- The frontend uses `http://localhost:{port}/api/v2/client` with header `client-uuid` for themes and storage.

## Tier / plan restrictions

Some endpoints or features may return:

```json
{
  "error_code": "FEATURE_IS_DISABLED_FOR_YOUR_PLAN",
  "message": "feature_is_disabled_for_your_plan"
}
```

See `API_TIER_BYPASS.md` for analysis and bypass options.

## Examples

### Create and start a profile from shell

```bash
PORT=$(cat ~/.Octo\ Browser/local_port)
BASE="http://localhost:$PORT"

# Create
RES=$(curl -s -X POST "$BASE/api/v2/profiles/quick" \
  -H "Content-Type: application/json" \
  -d '{"title": "Automation Profile", "os": "win"}')
UUID=$(echo "$RES" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['uuid'])")

# Start
curl -s -X POST "$BASE/api/v2/profiles/$UUID/start" \
  -H "Content-Type: application/json" \
  -d '{}'

# List to confirm
curl -s -X POST "$BASE/api/v2/profiles/list" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -m json.tool
```

### Check if API is up

```bash
curl -s http://localhost:58888/api/v2/client/themes && echo " OK" || echo " Down"
```
