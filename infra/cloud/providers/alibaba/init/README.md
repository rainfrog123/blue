# Xray Trojan + Cloudflare Tunnel Setup

## Architecture

```
Client --[HTTPS/443]--> Cloudflare CDN --[WebSocket]--> cloudflared --[http://xray-trojan:8080]--> xray-trojan
```

## Prerequisites

1. VPS with Docker installed
2. Domain on Cloudflare
3. Cloudflare Zero Trust account (free)

## Setup Steps

### 1. Create Cloudflare Tunnel

1. Go to https://one.dash.cloudflare.com/ → Networks → Tunnels
2. Create tunnel, name it (e.g., "x-trojan")
3. Copy the tunnel token (base64 string starting with `eyJ...`)
4. Add Public Hostname:
   - Subdomain: `x` (or any)
   - Domain: `yourdomain.com`
   - Service: `http://xray-trojan:8080`

### 2. Generate Credentials

```bash
# UUID for password
python3 -c "import uuid; print(uuid.uuid4())"

# Random path
python3 -c "import secrets; print('/' + secrets.token_hex(5))"
```

### 3. Create Files

**docker-compose.yml**

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
    command: tunnel --no-autoupdate run --token YOUR_TUNNEL_TOKEN
    networks:
      - tunnel-net
    depends_on:
      - xray-trojan

networks:
  tunnel-net:
    driver: bridge
```

**config.json**

```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 8080,
    "listen": "0.0.0.0",
    "protocol": "trojan",
    "settings": {
      "clients": [{"password": "YOUR_UUID", "email": "user@domain.com"}]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {"path": "/YOUR_RANDOM_PATH"}
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
```

### 4. Deploy

```bash
docker-compose up -d
docker-compose logs -f
```

## Client Configuration

| Setting   | Value                        |
|-----------|------------------------------|
| Address   | `subdomain.yourdomain.com`   |
| Port      | `443`                        |
| Password  | `YOUR_UUID`                  |
| Transport | WebSocket                    |
| WS Path   | `/YOUR_RANDOM_PATH`          |
| TLS       | Enabled                      |
| SNI       | `subdomain.yourdomain.com`   |

### Trojan URL

```
trojan://UUID@subdomain.domain.com:443?security=tls&type=ws&path=%2FPATH#Name
```

### Clash Format

```yaml
- {name: 'Name', type: trojan, server: subdomain.domain.com, port: 443, password: UUID, udp: true, sni: subdomain.domain.com, skip-cert-verify: false, network: ws, ws-opts: {path: /PATH}}
```

## Management Commands

```bash
docker-compose logs -f                        # View logs
docker-compose restart                        # Restart services
docker-compose down                           # Stop services
docker-compose pull && docker-compose up -d   # Update images
```

## Troubleshooting

```bash
docker logs xray-trojan    # Check Xray logs
docker logs cloudflared    # Check Cloudflared logs
```

## Current Instance (hyas.space zone)

| Setting   | Value                                  |
|-----------|----------------------------------------|
| Address   | `x.hyas.space`                         |
| Port      | `443`                                  |
| Password  | `ba19c9d6-3fc0-4085-9f47-465c5d7cceef` |
| WS Path   | `/x7f9k2m4p8`                          |
| Tunnel ID | `c9fc96f2-a367-4b91-bf18-b74c085325f4` |

**Trojan URL:**
```
trojan://ba19c9d6-3fc0-4085-9f47-465c5d7cceef@x.hyas.space:443?security=tls&type=ws&path=%2Fx7f9k2m4p8#Ali-Trojan
```

**Clash (Basic):**
```yaml
- {name: 'TJ|Ali|CF', type: trojan, server: x.hyas.space, port: 443, password: ba19c9d6-3fc0-4085-9f47-465c5d7cceef, udp: true, sni: x.hyas.space, skip-cert-verify: false, network: ws, ws-opts: {path: /x7f9k2m4p8}}
```

**Clash (With Preferred IP for China):**
```yaml
- name: 'TJ|Ali|CF|优选'
  type: trojan
  server: 162.159.25.200
  port: 443
  password: ba19c9d6-3fc0-4085-9f47-465c5d7cceef
  udp: true
  sni: x.hyas.space
  skip-cert-verify: false
  network: ws
  ws-opts:
    path: /x7f9k2m4p8
    headers:
      Host: x.hyas.space
```

## API Setup Commands (Reference)

```bash
# These commands were used to create this setup via CLI
cd /allah/blue/web/apps/cloudflare

# 1. Create tunnel
./cli.py tunnel create digi

# 2. Create DNS CNAME
./cli.py tunnel route-dns c9fc96f2-a367-4b91-bf18-b74c085325f4 x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316

# 3. Set fallback origin
./cli.py fallback set x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316

# 4. Create custom hostname
./cli.py hostname add x.hyas.space --zone-id 14a1737c5a43cdff29c09a606c162316

# 5. Configure tunnel ingress
./cli.py tunnel config set c9fc96f2-a367-4b91-bf18-b74c085325f4 --hostname x.hyas.space --service http://xray-trojan:8080

# 6. Get install token
./cli.py tunnel token c9fc96f2-a367-4b91-bf18-b74c085325f4
```
