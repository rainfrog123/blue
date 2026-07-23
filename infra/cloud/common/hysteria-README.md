# Hysteria 2 Server

> [!important] Port policy
> **Always use UDP `443`** for Hysteria 2 (Azure, Aliyun, and any new box). Do not use `5333` anymore.

## Deployed Servers

### Azure (Singapore) - IPv6 Only

| Setting | Value |
|---------|-------|
| **Server** | `hyaz.hyas.site:443` |
| **Port** | **443** (UDP) |
| **Password** | `NzPY5nTKThLxUb1MOJTuu6B0` |
| **IPv6** | `2603:1040:0:3::52` |

```
hysteria2://NzPY5nTKThLxUb1MOJTuu6B0@hyaz.hyas.site:443?sni=hyaz.hyas.site#Azure-SG-hy2
```

### Aliyun (Singapore) — current (`hy.hyas.site`)

| Setting | Value |
|---------|-------|
| **SS** | `47.237.141.29:12033` · `chacha20-ietf-poly1305` · `bxsnucrgk6hfish` |
| **Hy2** | `hy.hyas.site:**443**` · password `jEdTlnZe2q2nv1N0lmmXHCp2` |
| **IPv4** | `47.237.141.29` |
| **IPv6** | `240b:4000:20:ee00:eb99:2357:52aa:50a9` |
| **Compose** | `infra/cloud/ali/hysteria/` |

```
hysteria2://jEdTlnZe2q2nv1N0lmmXHCp2@hy.hyas.site:443?sni=hy.hyas.site#Ali-SG-hy2
```

### Digi / DigitalOcean (Singapore) — archived

Formerly `hy.hyas.site` on Digi `129.212.209.177` (Hy2 used to listen on **5333**; policy is now **443 only**). DNS and service moved to Aliyun above. Digi SS was on DO `188.166.252.16:12033`.

---

## Deploy on New Machine

### Prerequisites

- Docker installed
- Domain with Cloudflare DNS (grey cloud / DNS only)
- **UDP 443** open (security group / firewall)
- TCP **80** open for ACME HTTP-01 (and preferably TCP 443 unused by other listeners)

### Quick Deploy

```bash
# 1. Create directory (example: ali)
mkdir -p /allah/blue/infra/cloud/ali/hysteria && cd /allah/blue/infra/cloud/ali/hysteria

# 2. Generate password
openssl rand -base64 24 | tr -d '/+=' | head -c 24 && echo

# 3. Get server IPs
curl -4 -s ifconfig.me && echo    # IPv4
curl -6 -s ifconfig.me && echo    # IPv6
```

### config.yaml

**Always** `listen: :443`. Default **Brutal** bandwidth hint is `100 mbps` up/down (match Clash `up`/`down`):

```yaml
listen: :443

acme:
  domains:
    - SUBDOMAIN.hyas.site
  email: admin@hyas.site

auth:
  type: password
  password: YOUR_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

# Brutal CC hint (Clash client should also set up/down ≈ path capacity)
bandwidth:
  up: 100 mbps
  down: 100 mbps
```

### docker-compose.yml

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

### Add DNS Records

**Proxy must be OFF** (grey cloud) — Hysteria uses UDP.

```bash
cd /allah/blue/web/apps/cloudflare
python3 cli.py dns add --type A --name SUBDOMAIN --content IPV4
python3 cli.py dns add --type AAAA --name SUBDOMAIN --content IPV6
```

### Start Server

```bash
mkdir -p acme
docker compose up -d
docker logs -f hysteria2
```

Wait for `server up and running` with `listen: ":443"`.

---

## Client Config Templates

### Clash Meta / Mihomo

```yaml
proxies:
  - name: "NAME"
    type: hysteria2
    server: SUBDOMAIN.hyas.site
    port: 443
    password: PASSWORD
    sni: SUBDOMAIN.hyas.site
    up: 100
    down: 100
```

### Hysteria 2 Client

```yaml
server: SUBDOMAIN.hyas.site:443

auth: PASSWORD

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

### URI (mobile apps)

```
hysteria2://PASSWORD@SUBDOMAIN.hyas.site:443?sni=SUBDOMAIN.hyas.site#NAME
```

### NekoBox / Sing-box

```json
{
  "type": "hysteria2",
  "tag": "NAME",
  "server": "SUBDOMAIN.hyas.site",
  "server_port": 443,
  "password": "PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "SUBDOMAIN.hyas.site"
  }
}
```

---

## Operations

```bash
docker logs -f hysteria2
docker compose restart
docker compose down
docker compose pull && docker compose up -d
docker ps | grep hysteria
ss -ulnp | grep 443
```

---

## Troubleshooting

### ACME cert failed
- DNS must point to this server
- TCP **80** (HTTP-01) must be reachable
- Check: `dig SUBDOMAIN.hyas.site`

### Connection refused
- Open **UDP 443** in firewall / cloud SG
- Confirm: `ss -ulnp | grep 443` and logs show `listen: ":443"`

### Container restarting
- `docker logs hysteria2`
- Verify `config.yaml` uses `listen: :443`
