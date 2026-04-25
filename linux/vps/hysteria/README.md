# Hysteria 2 Server

## Server Info

| Setting | Value |
|---------|-------|
| **Server** | `hy.hyas.site:5333` |
| **Port** | `5333` (UDP) |
| **Password** | `jEdTlnZe2q2nv1N0lmmXHCp2` |
| **Protocol** | Hysteria 2 |

## DNS Setup Required

Add this DNS record in Cloudflare for `hyas.site`:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | hy | 129.212.209.177 | OFF (DNS only) |
| AAAA | hy | 2400:6180:0:d2:0:2:c7ec:0 | OFF (DNS only) |

**Important:** Proxy must be OFF (grey cloud) - Hysteria uses UDP which Cloudflare doesn't proxy.

## Start Server

```bash
cd /allah/blue/linux/vps/hysteria
docker compose up -d
docker logs -f hysteria2
```

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

## Useful Commands

```bash
# View logs
docker logs -f hysteria2

# Restart
docker compose restart

# Stop
docker compose down

# Update image
docker compose pull && docker compose up -d
```
