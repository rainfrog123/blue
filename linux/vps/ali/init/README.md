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

## Current Instance

| Setting   | Value                                  |
|-----------|----------------------------------------|
| Address   | `x.hyas.site`                          |
| Port      | `443`                                  |
| Password  | `ba19c9d6-3fc0-4085-9f47-465c5d7cceef` |
| WS Path   | `/x7f9k2m4p8`                          |

**Trojan URL:**
```
trojan://ba19c9d6-3fc0-4085-9f47-465c5d7cceef@x.hyas.site:443?security=tls&type=ws&path=%2Fx7f9k2m4p8#X-Trojan
```

**Clash:**
```yaml
- {name: 'TJ|X|CF', type: trojan, server: x.hyas.site, port: 443, password: ba19c9d6-3fc0-4085-9f47-465c5d7cceef, udp: true, sni: x.hyas.site, skip-cert-verify: false, network: ws, ws-opts: {path: /x7f9k2m4p8}}
```
