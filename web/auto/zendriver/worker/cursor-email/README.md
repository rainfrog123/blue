# Cursor Email Verification Worker

Cloudflare Worker that receives verification emails and extracts OTP codes.

## Setup

1. **Install dependencies:**
```bash
cd cursor-email
npm install
```

2. **Create KV namespace:**
```bash
wrangler kv namespace create CODES
```
Copy the ID and update `wrangler.toml`.

3. **Deploy:**
```bash
export CLOUDFLARE_API_TOKEN="your-token"
wrangler deploy
```

4. **Set up Email Routing in Cloudflare Dashboard:**
   - Go to your domain → Email → Email Routing
   - Add a custom address that routes to this worker

## API Usage

**Get verification code:**
```bash
curl "https://cursor-email-worker.YOUR_SUBDOMAIN.workers.dev/code?email=your@email.com"
```

**Response:**
```json
{
  "code": "706660",
  "service": "cursor",
  "email": "your@email.com",
  "expiresIn": 540
}
```

**Manual code entry (for testing):**
```bash
curl -X POST "https://cursor-email-worker.YOUR_SUBDOMAIN.workers.dev/code" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "code": "123456", "service": "cursor"}'
```

## Python Usage

```python
import requests

def get_cursor_code(email: str, worker_url: str) -> str | None:
    resp = requests.get(f"{worker_url}/code", params={"email": email, "service": "cursor"})
    if resp.status_code == 200:
        return resp.json()["code"]
    return None
```
