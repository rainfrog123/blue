# Hysteria 2 Server

> [!important] Port policy
> **Always use UDP `443`** for Hysteria 2 (Azure, Aliyun, and any new box). Do not use `5333` anymore.

> [!tip] Shared defaults
> Brutal bandwidth, listen, and masquerade live in **one** file: `infra/cloud/common/hysteria/defaults.yaml`.
> Each VPS only has `site.yaml` (ACME domain + password). `up.sh` merges them into `config.yaml` before compose.

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

### Digi / DigitalOcean (Singapore)

| Setting | Value |
|---------|-------|
| **Hy2** | `hyd.hyas.site:**443**` · same password as Ali |
| **Compose** | `infra/cloud/digi/hysteria/` |

Formerly `hy.hyas.site` on Digi `129.212.209.177` (Hy2 used to listen on **5333**; policy is now **443 only**).

---

## Layout

```
infra/cloud/common/hysteria/defaults.yaml   # listen, masquerade, bandwidth (Brutal 100/100)
infra/cloud/common/hysteria/render.py       # merges → config.yaml
infra/cloud/common/hysteria/up.sh           # render + docker compose
infra/cloud/<vps>/hysteria/site.yaml        # acme + auth only
infra/cloud/<vps>/hysteria/docker-compose.yml
infra/cloud/<vps>/hysteria/config.yaml      # generated (gitignored)
```

### defaults.yaml (shared — edit once)

```yaml
listen: :443

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

bandwidth:
  up: 100 mbps
  down: 100 mbps
```

### site.yaml (per box)

```yaml
acme:
  domains:
    - SUBDOMAIN.hyas.site
  email: admin@hyas.site

auth:
  type: password
  password: YOUR_PASSWORD
```

---

## Deploy on New Machine

### Prerequisites

- Docker installed
- Domain with Cloudflare DNS (grey cloud / DNS only)
- **UDP 443** open (security group / firewall)
- TCP **80** open for ACME HTTP-01 (and preferably TCP 443 unused by other listeners)

### Quick Deploy

```bash
# 1. Create directory (example: ali) — usually already in the blue repo
mkdir -p /allah/blue/infra/cloud/NEWBOX/hysteria/acme
cd /allah/blue/infra/cloud/NEWBOX/hysteria

# 2. Generate password
openssl rand -base64 24 | tr -d '/+=' | head -c 24 && echo

# 3. Write site.yaml (domain + password only), copy docker-compose from digi/ali

# 4. Get server IPs
curl -4 -s ifconfig.me && echo    # IPv4
curl -6 -s ifconfig.me && echo    # IPv6
```

### Start Server

```bash
mkdir -p acme
bash /allah/blue/infra/cloud/common/hysteria/up.sh ali up -d
docker logs -f hysteria2
```

Wait for `server up and running` with `listen: ":443"`.

Preview merged config without writing:

```bash
python3 infra/cloud/common/hysteria/render.py ali --stdout
```

### Add DNS Records

**Proxy must be OFF** (grey cloud) — Hysteria uses UDP.

```bash
cd /allah/blue/web/apps/cloudflare
python3 cli.py dns add --type A --name SUBDOMAIN --content IPV4
python3 cli.py dns add --type AAAA --name SUBDOMAIN --content IPV6
```

---

## Client Config Templates

### Clash Meta / Mihomo

Always set `up`/`down` to match server Brutal hint (default **100**):

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
bash infra/cloud/common/hysteria/up.sh ali up -d
docker logs -f hysteria2
docker compose -f infra/cloud/ali/hysteria/docker-compose.yml restart
docker ps | grep hysteria
ss -ulnp | grep 443
# Confirm Brutal defaults landed:
python3 infra/cloud/common/hysteria/render.py ali --stdout | grep -A2 bandwidth
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
- Re-render: `python3 infra/cloud/common/hysteria/render.py ali`
- Confirm `config.yaml` contains both `bandwidth` and site `acme`/`auth`
