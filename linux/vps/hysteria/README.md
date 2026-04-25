# Hysteria 2 Server

## Deployed Servers

### Azure (Singapore) - IPv6 Only

| Setting | Value |
|---------|-------|
| **Server** | `hyaz.hyas.site:3365` |
| **Port** | `3365` (UDP) |
| **Password** | `NzPY5nTKThLxUb1MOJTuu6B0` |
| **IPv6** | `2603:1040:0:3::52` |

```
hysteria2://NzPY5nTKThLxUb1MOJTuu6B0@hyaz.hyas.site:3365?sni=hyaz.hyas.site#Azure-SG-hy2
```

### DigitalOcean (Singapore)

| Setting | Value |
|---------|-------|
| **Server** | `hy.hyas.site:5333` |
| **Port** | `5333` (UDP) |
| **Password** | `jEdTlnZe2q2nv1N0lmmXHCp2` |
| **IPv4** | `129.212.209.177` |
| **IPv6** | `2400:6180:0:d2:0:2:c7ec:0` |

```
hysteria2://jEdTlnZe2q2nv1N0lmmXHCp2@hy.hyas.site:5333?sni=hy.hyas.site#DO-SG-hy2
```

---

## Deploy on New Machine

### Prerequisites

- Docker installed
- Domain with Cloudflare DNS
- UDP port open (firewall/security group)
- Ports 80/443 accessible for ACME certificate

### Quick Deploy

```bash
# 1. Create directory
mkdir -p /allah/blue/linux/vps/hysteria && cd /allah/blue/linux/vps/hysteria

# 2. Generate password
openssl rand -base64 24 | tr -d '/+=' | head -c 24 && echo

# 3. Get server IPs
curl -4 -s ifconfig.me && echo    # IPv4
curl -6 -s ifconfig.me && echo    # IPv6
```

### config.yaml

```yaml
listen: :PORT

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

**Proxy must be OFF** (grey cloud) - Hysteria uses UDP.

```bash
cd /allah/blue/web/apps/cloudflare
python3 cli.py dns add --type A --name SUBDOMAIN --content IPV4
python3 cli.py dns add --type AAAA --name SUBDOMAIN --content IPV6
```

### Start Server

```bash
mkdir -p acme
docker-compose up -d
docker logs -f hysteria2
```

Wait for `server up and running` in logs.

---

## Client Config Templates

### Clash Meta / Mihomo

```yaml
proxies:
  - name: "NAME"
    type: hysteria2
    server: SUBDOMAIN.hyas.site
    port: PORT
    password: PASSWORD
    sni: SUBDOMAIN.hyas.site
```

### Hysteria 2 Client

```yaml
server: SUBDOMAIN.hyas.site:PORT

auth: PASSWORD

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

### URI (mobile apps)

```
hysteria2://PASSWORD@SUBDOMAIN.hyas.site:PORT?sni=SUBDOMAIN.hyas.site#NAME
```

### NekoBox / Sing-box

```json
{
  "type": "hysteria2",
  "tag": "NAME",
  "server": "SUBDOMAIN.hyas.site",
  "server_port": PORT,
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
docker logs -f hysteria2        # View logs
docker-compose restart          # Restart
docker-compose down             # Stop
docker-compose pull && docker-compose up -d   # Update
docker ps | grep hysteria       # Check status
ss -ulnp | grep PORT            # Check port
```

---

## Troubleshooting

### ACME cert failed
- DNS record must point to server IP
- Ports 80/443 must be open for ACME challenge
- Check: `dig SUBDOMAIN.hyas.site`

### Connection refused
- Open UDP port in firewall: `ufw allow PORT/udp`
- Check cloud security group allows UDP inbound

### Container restarting
- Check logs: `docker logs hysteria2`
- Verify config.yaml syntax
