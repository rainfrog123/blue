# Cloudflare Email Routing Setup

## Account Info
- **Email:** mao@ceto.site
- **Account ID:** 5d75ad91bc621086a1908973590051c3
- **Domain:** hyas.site
- **Zone ID:** 2c5bc584bd4a638c9b6a36a85dc591cb

---

## What Was Configured

### 1. Email Routing
Email routing enabled for `hyas.site` via API.

### 2. DNS Records (Auto-configured)
| Type | Name | Content |
|------|------|---------|
| MX | hyas.site | route1.mx.cloudflare.net (priority 44) |
| MX | hyas.site | route2.mx.cloudflare.net (priority 27) |
| MX | hyas.site | route3.mx.cloudflare.net (priority 60) |
| TXT | hyas.site | v=spf1 include:_spf.mx.cloudflare.net ~all |

### 3. Worker Created
- **Name:** `hyas-mail`
- **Function:** Receives emails, extracts OTP codes, logs to console

### 4. Email Routes
| Address | Action |
|---------|--------|
| otp@hyas.site | → worker: hyas-mail |
| cursor@hyas.site | → worker: hyas-mail |
| verify@hyas.site | → worker: hyas-mail |
| code@hyas.site | → worker: hyas-mail |
| *@hyas.site (catch-all) | drop (disabled) |

---

## Free Tier Limits

### Workers
| Resource | Limit |
|----------|-------|
| Requests/day | 100,000 |

### KV (Key-Value)
| Resource | Limit |
|----------|-------|
| Read ops/day | 100,000 |
| Write ops/day | 1,000 |
| Storage | 1 GB |

### D1 (SQL Database)
| Resource | Limit |
|----------|-------|
| Rows read/day | 5,000,000 |
| Rows written/day | 100,000 |
| Storage | 5 GB |

---

## Storage

### KV Namespace (OTPs)
- **Name:** cursor-otp
- **ID:** b7c6dfb18dce4914bc0b93887cc83a9b
- **Purpose:** Store OTPs for quick lookup (expires in 10 min)

### D1 Database (All Emails)
- **Name:** cursor-emails
- **ID:** 3a703fbd-0081-4863-abeb-2fab432f78b4
- **Purpose:** Permanent storage of all received emails

**Table Schema:**
```sql
CREATE TABLE emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT,
    otp TEXT,
    raw_body TEXT,
    received_at TEXT NOT NULL
);
```

---

## Worker Code

The `hyas-mail` worker:
1. Extracts OTP from Cursor emails (pattern: 6 digits)
2. Saves OTP to KV (key = recipient email, TTL = 10 min)
3. Saves full email to D1 database

```javascript
export default {
  async email(message, env, ctx) {
    const to = message.to;
    const from = message.from;
    const subject = message.headers.get("subject") || "";
    const rawEmail = await new Response(message.raw).text();
    const timestamp = new Date().toISOString();
    
    // Extract OTP - any 6-digit number (works for any language)
    const otpMatch = rawEmail.match(/\b\d{6}\b/);
    const otp = otpMatch ? otpMatch[0] : null;
    
    // Save OTP to KV (expires in 10 minutes)
    if (otp && env.OTP_KV) {
      await env.OTP_KV.put(to, JSON.stringify({
        otp, from, subject, timestamp
      }), { expirationTtl: 600 });
    }
    
    // Save full email to D1
    if (env.EMAILS_DB) {
      await env.EMAILS_DB.prepare(
        "INSERT INTO emails (recipient, sender, subject, otp, raw_body, received_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(to, from, subject, otp, rawEmail, timestamp).run();
    }
    
    message.setReject(false);
  }
};
```

---

## Usage

### Check Usage Limits
```bash
python checker.py
```

### Add New Email Address
```python
import requests
from cred_loader import get_cloudflare

creds = get_cloudflare()
headers = {
    'X-Auth-Email': creds['email'],
    'X-Auth-Key': creds['global_api_key'],
    'Content-Type': 'application/json'
}

zone_id = '2c5bc584bd4a638c9b6a36a85dc591cb'

requests.post(
    f'https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules',
    headers=headers,
    json={
        'matchers': [{'type': 'literal', 'field': 'to', 'value': 'newaddr@hyas.site'}],
        'actions': [{'type': 'worker', 'value': ['hyas-mail']}],
        'enabled': True,
        'name': 'newaddr emails to worker'
    }
)
```

### View Worker Logs
```bash
wrangler tail hyas-mail
```

### Read OTP from KV
```python
import requests
from cred_loader import get_cloudflare

creds = get_cloudflare()
headers = {
    'X-Auth-Email': creds['email'],
    'X-Auth-Key': creds['global_api_key'],
}

account_id = '5d75ad91bc621086a1908973590051c3'
kv_id = 'b7c6dfb18dce4914bc0b93887cc83a9b'
email = 'test@hyas.site'

resp = requests.get(
    f'https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{kv_id}/values/{email}',
    headers=headers
)
print(resp.text)  # {"otp": "001712", "from": "...", ...}
```

### Query Emails from D1
```python
import requests
from cred_loader import get_cloudflare

creds = get_cloudflare()
headers = {
    'X-Auth-Email': creds['email'],
    'X-Auth-Key': creds['global_api_key'],
    'Content-Type': 'application/json'
}

account_id = '5d75ad91bc621086a1908973590051c3'
d1_id = '3a703fbd-0081-4863-abeb-2fab432f78b4'

resp = requests.post(
    f'https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{d1_id}/query',
    headers=headers,
    json={'sql': 'SELECT * FROM emails ORDER BY id DESC LIMIT 10'}
)
print(resp.json())
```

---

## Files
- `checker.py` - Check Cloudflare usage limits
- `CLOUDFLARE_SETUP.md` - This documentation



https://hyas-mail.mao-5d7.workers.dev