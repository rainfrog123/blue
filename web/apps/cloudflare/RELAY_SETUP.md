# Relay Architecture Setup

## Current Deployments

### Zone: hyas.site (Original)

| Component | Name | ID | Status |
|-----------|------|-----|--------|
| **Tunnel** | `x` | `6b2a1433-b8f1-4aa6-86ed-0b4df4013ef3` | healthy |
| **Custom Hostname** | `x.hyas.site` | `b366b1e4-6a2f-4802-90fc-3d7ebc4fdc10` | SSL active |
| **Fallback Origin** | `x.hyas.site` | — | active |
| **DNS CNAME** | `x.hyas.site` | → `6b2a1433-...cfargotunnel.com` | proxied |

### Zone: hyas.space (Ali VPS - 2026-03-30)

| Component | Name | ID | Status |
|-----------|------|-----|--------|
| **Tunnel** | `digi` | `c9fc96f2-a367-4b91-bf18-b74c085325f4` | healthy |
| **Custom Hostname** | `x.hyas.space` | `c74e4900-4b7b-4d43-8975-18392a1db610` | SSL active |
| **Fallback Origin** | `x.hyas.space` | — | active |
| **DNS CNAME** | `x.hyas.space` | → `c9fc96f2-...cfargotunnel.com` | proxied |

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

## Multi-Zone Strategy (Multiple Tunnels with Preferred IP)

**Problem:** Each Cloudflare zone only allows ONE fallback origin. If you need multiple tunnels with preferred IP support, you can't use the same zone.

**Solution:** Use separate zones for each tunnel.

| Zone | Tunnel | Custom Hostname | Use Case |
|------|--------|-----------------|----------|
| `hyas.site` | `x` | `x.hyas.site` | Primary VPS |
| `hyas.space` | `digi` | `x.hyas.space` | Ali VPS |

This gives each tunnel independent:
- Custom Hostname (SNI domain)
- Fallback Origin
- SSL certificate
- Preferred IP support

## CLI Commands

```bash
# Check current setup
./cli.py tunnel list
./cli.py hostname list
./cli.py fallback get
./cli.py dns list --type CNAME

# Check specific zone (hyas.space)
./cli.py hostname list --zone-id 14a1737c5a43cdff29c09a606c162316
./cli.py fallback get --zone-id 14a1737c5a43cdff29c09a606c162316

# Get tunnel token (for VPS setup)
./cli.py tunnel token c9fc96f2-a367-4b91-bf18-b74c085325f4

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

## Complete API Workflow (Proven 2026-03-30)

### Step 1: Create Tunnel
```bash
./cli.py tunnel create digi
# Output: Tunnel ID c9fc96f2-a367-4b91-bf18-b74c085325f4
```

### Step 2: Create DNS CNAME
```bash
./cli.py tunnel route-dns c9fc96f2-a367-4b91-bf18-b74c085325f4 x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316
# Creates: x.hyas.space → c9fc96f2-...cfargotunnel.com (proxied)
```

### Step 3: Set Fallback Origin
```bash
./cli.py fallback set x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316
```

### Step 4: Create Custom Hostname
```bash
./cli.py hostname add x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316
# SSL auto-provisions in ~30 seconds
```

### Step 5: Configure Tunnel Ingress
```bash
./cli.py tunnel config set c9fc96f2-a367-4b91-bf18-b74c085325f4 --hostname x.hyas.space --service http://xray-trojan:8080
```

### Step 6: Get Install Token
```bash
./cli.py tunnel token c9fc96f2-a367-4b91-bf18-b74c085325f4
# Output: eyJhIjoiNWQ3NWFk...
```

## VPS Setup (Docker Compose - Recommended)

### docker-compose.yml
```yaml
version: "3.8"

services:
  xray-trojan:
    image: ghcr.io/xtls/xray-core:latest
    container_name: xray-trojan
    restart: always
    volumes:
      - ./config.json:/etc/xray/config.json
    command: run -c /etc/xray/config.json
    networks:
      - tunnel-net

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    restart: always
    command: tunnel --no-autoupdate run --token <YOUR_TOKEN>
    networks:
      - tunnel-net
    depends_on:
      - xray-trojan

networks:
  tunnel-net:
    driver: bridge
```

### config.json (Xray Trojan)
```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 8080,
    "listen": "0.0.0.0",
    "protocol": "trojan",
    "settings": {
      "clients": [{"password": "ba19c9d6-3fc0-4085-9f47-465c5d7cceef", "email": "user@x.hyas.space"}]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {"path": "/x7f9k2m4p8"}
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
```

### Deploy
```bash
cd /allah/blue/linux/vps/ali/init
docker-compose up -d
docker-compose logs -f
```

## VPS Setup (Systemd - Alternative)

```bash
# Install cloudflared
curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# Install as service with token
cloudflared service install <token>

# Check status
systemctl status cloudflared
```

## Client Configs

### Basic (No Preferred IP)
```yaml
- name: 'TJ|Ali|CF'
  type: trojan
  server: x.hyas.space
  port: 443
  password: ba19c9d6-3fc0-4085-9f47-465c5d7cceef
  udp: true
  sni: x.hyas.space
  skip-cert-verify: false
  network: ws
  ws-opts:
    path: /x7f9k2m4p8
```

### With Preferred IP (China Optimization)
```yaml
- name: 'TJ|Ali|CF|优选'
  type: trojan
  server: 162.159.25.200    # Preferred Cloudflare IP
  port: 443
  password: ba19c9d6-3fc0-4085-9f47-465c5d7cceef
  udp: true
  sni: x.hyas.space
  skip-cert-verify: false
  network: ws
  ws-opts:
    path: /x7f9k2m4p8
    headers:
      Host: x.hyas.space    # REQUIRED with preferred IP
```

### Trojan URL (for import)
```
trojan://ba19c9d6-3fc0-4085-9f47-465c5d7cceef@x.hyas.space:443?security=tls&type=ws&path=%2Fx7f9k2m4p8#Ali-Trojan
```

## Tested Cloudflare Preferred IPs

From China mainland testing (2026):

| IP | Latency | Speed | Region | Notes |
|----|---------|-------|--------|-------|
| `162.159.38.214` | 85ms | 47.76 MB/s | NRT | Best |
| `162.159.44.106` | 87ms | 45.79 MB/s | NRT | |
| `172.64.53.139` | 85ms | 44.83 MB/s | NRT | |
| `162.159.34.174` | 85ms | 43.51 MB/s | SIN | |
| `162.159.45.111` | 85ms | 39.00 MB/s | NRT | |
| `162.159.25.200` | - | - | SIN | Stable |

## Zone IDs Reference

| Zone | Zone ID | Primary Use |
|------|---------|-------------|
| `hyas.site` | `2c5bc584bd4a638c9b6a36a85dc591cb` | Original relay |
| `hyas.space` | `14a1737c5a43cdff29c09a606c162316` | Ali VPS relay |
