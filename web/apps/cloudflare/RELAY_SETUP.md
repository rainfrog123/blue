# Relay Architecture Setup

## Current Configuration

| Component | Name | ID | Status |
|-----------|------|-----|--------|
| **Tunnel** | `x` | `6b2a1433-b8f1-4aa6-86ed-0b4df4013ef3` | healthy |
| **Custom Hostname** | `x.hyas.site` | `b366b1e4-6a2f-4802-90fc-3d7ebc4fdc10` | SSL active |
| **Fallback Origin** | `x.hyas.site` | — | active |
| **DNS CNAME** | `x.hyas.site` | → `6b2a1433-...cfargotunnel.com` | proxied |

## Architecture Diagram

```
Client (preferred IP + SNI: x.hyas.site)
                │
                ▼
┌─────────────────────────────────┐
│  Custom Hostname: x.hyas.site   │  SSL: active
│  Fallback Origin: x.hyas.site   │
└─────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│  DNS CNAME (proxied)                                    │
│  x.hyas.site → 6b2a1433-b8f1-4aa6-86ed-0b4df4013ef3    │
│                .cfargotunnel.com                        │
└─────────────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│  Tunnel: x                      │  Status: healthy
│  ID: 6b2a1433-b8f1-4aa6-...     │
└─────────────────────────────────┘
                │
                ▼
           Your VPS (cloudflared → Trojan-Go)
```

## How It Works (The "Relay Race")

### 1. Entry Point: Preferred IP (The "Front Door")

**Client Config:** `server: 162.159.25.200` (example)

- This is the Anycast IP of a Cloudflare Edge node
- By manually picking a "Preferred IP" (优选 IP), you bypass congested default IPs
- To the ISP/Firewall, you're just connecting to a standard Cloudflare IP

### 2. The Handshake: SNI (The "ID Card")

**Client Config:** `sni: x.hyas.site`

- During TLS handshake, client sends the Server Name Indication (SNI)
- Cloudflare's edge recognizes `x.hyas.site` via the Custom Hostname
- It presents the SSL certificate and establishes the connection

### 3. The Logic: Custom Hostname & Fallback Origin (The "Router")

**Dashboard:** `x.hyas.site` → Fallback Origin → Tunnel

- Custom Hostname tells the Edge: "If you receive a request for this domain, route it to the Fallback Origin"
- Acts as an internal symlink within Cloudflare's network

### 4. The Bridge: Cloudflare Tunnel (`cloudflared`)

**VPS:** The daemon running on your server

- Creates an **outbound** connection to Cloudflare (no open ports needed)
- Persistent encrypted pipe (QUIC) waiting for data
- Your VPS firewall can deny all incoming traffic

### 5. The Payload: Trojan-Go over WebSockets (The "Disguise")

**Client Config:** `network: ws`, `path: /x7f9k2m4p8`

- Trojan wrapped in WebSocket looks like standard web traffic
- Path acts as secondary authentication
- Cloudflare proxies it as normal HTTPS/WebSocket

## Why This is Firewall-Proof

The firewall sees:
- ✅ HTTPS/TLS connection
- ✅ To a reputable Cloudflare IP
- ✅ With a valid SSL certificate
- ✅ Carrying WebSocket traffic (standard web behavior)

No leakage of:
- ❌ VPS's real IP address
- ❌ Suspicious non-web protocols

## CLI Commands

```bash
# Check current setup
./cli.py tunnel list
./cli.py hostname list
./cli.py fallback get
./cli.py dns list --type CNAME

# Get tunnel token (for VPS setup)
./cli.py tunnel token 6b2a1433-b8f1-4aa6-86ed-0b4df4013ef3

# One-click setup (creates new relay)
./cli.py setup relay \
    --tunnel-name my-relay \
    --tunnel-subdomain tunnel.hyas.site \
    --custom-hostname y.hyas.site

# Teardown
./cli.py setup teardown \
    --tunnel-id <id> \
    --hostname-id <id> \
    --dns-record-id <id>
```

## VPS Setup Commands

```bash
# Install cloudflared
curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# Install as service with token
cloudflared service install <token>

# Check status
systemctl status cloudflared
```

## Client Config Template

```yaml
server: <preferred-cloudflare-ip>
sni: x.hyas.site
host: x.hyas.site
port: 443
network: ws
path: /your-secret-path
password: your-trojan-password
```
