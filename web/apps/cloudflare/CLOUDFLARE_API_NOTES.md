# Cloudflare Email Routing API - Lessons Learned

## The Problem

Tried to modify the catch-all email rule via the standard rules API:

```python
# This does NOT work for catch-all rules
requests.put(
    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules/{rule_id}',
    headers=headers,
    json={
        'matchers': [{'type': 'all'}],
        'actions': [{'type': 'worker', 'value': ['email-to-api']}],
        'enabled': True
    }
)
# Returns: 409 - "Invalid rule operation"
```

Also tried to delete and recreate:

```python
# This also does NOT work
requests.delete(
    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules/{rule_id}',
    headers=headers
)
# Returns: 409 - "Invalid rule operation"
```

## The Solution

Cloudflare has a **dedicated endpoint** for the catch-all rule:

```
/zones/{zone_id}/email/routing/rules/catch_all
```

This endpoint accepts GET and PUT, but the rule cannot be deleted.

### Working Code

```python
import requests

zone_id = '2c5bc584bd4a638c9b6a36a85dc591cb'
headers = {
    'X-Auth-Email': 'your-email',
    'X-Auth-Key': 'your-global-api-key',
    'Content-Type': 'application/json'
}

# GET current catch-all settings
resp = requests.get(
    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules/catch_all',
    headers=headers
)

# PUT to update catch-all (this WORKS!)
resp = requests.put(
    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules/catch_all',
    headers=headers,
    json={
        'matchers': [{'type': 'all'}],
        'actions': [{'type': 'worker', 'value': ['email-to-api']}],
        'enabled': True,
        'name': 'Catch-all to worker'
    }
)
# Returns: 200 - Success!
```

## API Endpoints Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/zones/{zone_id}/email/routing` | GET | Check email routing status |
| `/zones/{zone_id}/email/routing/enable` | POST | Enable email routing |
| `/zones/{zone_id}/email/routing/disable` | POST | Disable email routing |
| `/zones/{zone_id}/email/routing/rules` | GET | List all rules |
| `/zones/{zone_id}/email/routing/rules` | POST | Create new rule (NOT catch-all) |
| `/zones/{zone_id}/email/routing/rules/{id}` | PUT/DELETE | Modify/delete rule (NOT catch-all) |
| `/zones/{zone_id}/email/routing/rules/catch_all` | GET/PUT | **Catch-all rule (special endpoint)** |

## Action Types

| Type | Value | Description |
|------|-------|-------------|
| `drop` | - | Silently drop the email |
| `forward` | `["dest@email.com"]` | Forward to another email |
| `worker` | `["worker-name"]` | Send to a Worker |

## Matcher Types

| Type | Field | Value | Description |
|------|-------|-------|-------------|
| `all` | - | - | Catch-all (any recipient) |
| `literal` | `to` | `user@domain.com` | Exact match |

## Key Takeaways

1. **Catch-all is special** - Use `/rules/catch_all` endpoint, not `/rules/{id}`
2. **Cannot delete catch-all** - You can only modify or disable it
3. **Worker must exist first** - Create the worker before referencing it in rules
4. **Email routing must be enabled** - Call `/email/routing/enable` first
5. **DNS is auto-configured** - MX and SPF records are added automatically when email routing is enabled

## Authentication

Two options:

### Global API Key (requires email)
```python
headers = {
    'X-Auth-Email': 'your-email@example.com',
    'X-Auth-Key': 'your-global-api-key',
    'Content-Type': 'application/json'
}
```

### API Token (standalone)
```python
headers = {
    'Authorization': 'Bearer your-api-token',
    'Content-Type': 'application/json'
}
```

## Full Setup Sequence

```python
# 1. Enable email routing
requests.post(f'.../zones/{zone_id}/email/routing/enable', headers=headers)

# 2. Create worker
requests.put(
    f'.../accounts/{account_id}/workers/scripts/email-to-api',
    headers=headers_form,
    files={
        'metadata': (None, '{"main_module": "worker.js"}', 'application/json'),
        'worker.js': ('worker.js', WORKER_CODE, 'application/javascript+module')
    }
)

# 3. Set catch-all to worker
requests.put(
    f'.../zones/{zone_id}/email/routing/rules/catch_all',
    headers=headers,
    json={
        'matchers': [{'type': 'all'}],
        'actions': [{'type': 'worker', 'value': ['email-to-api']}],
        'enabled': True
    }
)
```
