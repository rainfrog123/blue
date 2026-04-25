# Hysteria 2 Server

## Current Server Info (DO Singapore)

| Setting | Value |
|---------|-------|
| **Server** | `hy.hyas.site:5333` |
| **Port** | `5333` (UDP) |
| **Password** | `jEdTlnZe2q2nv1N0lmmXHCp2` |
| **Protocol** | Hysteria 2 |
| **IPv4** | `129.212.209.177` |
| **IPv6** | `2400:6180:0:d2:0:2:c7ec:0` |

---

## Setup on New Machine

### Prerequisites

- Docker installed (`docker --version`)
- Domain with Cloudflare DNS (for ACME TLS cert)
- UDP port open (firewall/security group)

### Step 1: Create Directory

```bash
mkdir -p /allah/blue/linux/vps/hysteria
cd /allah/blue/linux/vps/hysteria
```

### Step 2: Generate Random Password

```bash
openssl rand -base64 24 | tr -d '/+=' | head -c 24
```

### Step 3: Get Server IP

```bash
curl -4 -s ifconfig.me    # IPv4
curl -6 -s ifconfig.me    # IPv6
```

### Step 4: Create config.yaml

```yaml
listen: :PORT

acme:
  domains:
    - SUBDOMAIN.DOMAIN.TLD
  email: admin@DOMAIN.TLD

auth:
  type: password
  password: YOUR_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
```

### Step 5: Create docker-compose.yml

```yaml
services:
  hysteria:
    image: tobyxdd/hysteria:v2
    container_name: hysteria2
    restart: always
    network_mode: host
    volumes:
      - ./config.yaml:/etc/hysteria/config.yaml:ro
      - ./acme:/etc/hysteria/acme
    command: ["server", "-c", "/etc/hysteria/config.yaml"]
```

### Step 6: Add DNS Record (Cloudflare)

**IMPORTANT:** Proxy must be OFF (DNS only / grey cloud) - Hysteria uses UDP.

Using CF CLI (`/allah/blue/web/apps/cloudflare`):

```bash
cd /allah/blue/web/apps/cloudflare
python3 cli.py dns add --type A --name SUBDOMAIN --content SERVER_IPV4
python3 cli.py dns add --type AAAA --name SUBDOMAIN --content SERVER_IPV6
```

Or manually in Cloudflare dashboard:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | hy | 1.2.3.4 | OFF |
| AAAA | hy | 2001:db8::1 | OFF |

### Step 7: Start Server

```bash
mkdir -p acme
docker-compose up -d
docker logs -f hysteria2
```

Wait for `server up and running` and `certificate obtained successfully` in logs.

### Step 8: Add to Clash Config

Add node to `/allah/blue/linux/extra/network/blue.yml`:

```yaml
proxies:
  - name: 🇸🇬LOCATION_hy2
    type: hysteria2
    server: SUBDOMAIN.DOMAIN.TLD
    port: PORT
    password: YOUR_PASSWORD
    sni: SUBDOMAIN.DOMAIN.TLD
```

Add to Manual Selection group:

```yaml
  - name: 🔑 Manual Selection
    type: select
    proxies:
      - 🇸🇬LOCATION_hy2
      # ... other nodes
```

---

## Client Configs

### Clash Meta / Mihomo

```yaml
proxies:
  - name: "Hysteria2-HY"
    type: hysteria2
    server: hy.hyas.site
    port: 5333
    password: jEdTlnZe2q2nv1N0lmmXHCp2
    sni: hy.hyas.site
```

### Hysteria 2 Client (config.yaml)

```yaml
server: hy.hyas.site:5333

auth: jEdTlnZe2q2nv1N0lmmXHCp2

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

### URI (for mobile apps)

```
hysteria2://jEdTlnZe2q2nv1N0lmmXHCp2@hy.hyas.site:5333?sni=hy.hyas.site#Hysteria2-HY
```

### NekoBox / Sing-box

```json
{
  "type": "hysteria2",
  "tag": "hysteria2-hy",
  "server": "hy.hyas.site",
  "server_port": 5333,
  "password": "jEdTlnZe2q2nv1N0lmmXHCp2",
  "tls": {
    "enabled": true,
    "server_name": "hy.hyas.site"
  }
}
```

---

## Operations

```bash
# View logs
docker logs -f hysteria2

# Restart
docker-compose restart

# Stop
docker-compose down

# Update image
docker-compose pull && docker-compose up -d

# Check if running
docker ps | grep hysteria

# Check port listening
ss -ulnp | grep PORT
```

---

## Troubleshooting

### ACME cert failed
- Verify DNS record exists and points to this server
- Ensure port 80 is accessible (for HTTP-01 challenge)
- Check domain resolves: `dig SUBDOMAIN.DOMAIN.TLD`

### Connection refused
- Check UDP port is open in firewall: `ufw allow PORT/udp`
- Check security group allows UDP inbound

### Container keeps restarting
- Check logs: `docker logs hysteria2`
- Verify config.yaml syntax is valid
