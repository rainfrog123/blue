# Xray REALITY + WARP Setup

VLESS with REALITY protocol for undetectable proxy, plus Cloudflare Tunnel option. All outbound via Cloudflare WARP for clean IP.

## Features

- **REALITY Protocol** (Direct): Looks like legitimate HTTPS to microsoft.com - impossible to detect/block
- **VLESS+WS via CF Tunnel**: Hides server IP completely behind Cloudflare
- **WARP Outbound**: Traffic exits via Cloudflare's clean IP pool (not your VPS IP)

---

## Option 1: Direct REALITY (Fastest)

Direct connection to VPS port 443. Best performance, undetectable protocol.

| Setting | Value |
|---------|-------|
| Address | `188.166.252.16` |
| Port | `443` |
| Protocol | VLESS |
| UUID | `061527a1-af84-4688-87d1-f08edf0dc8b4` |
| Flow | `xtls-rprx-vision` |
| Security | REALITY |
| SNI | `www.microsoft.com` |
| Public Key | `w7QKHjzAPCl6_V_HlezcQGCe4dkntvOo3JGpc-7tZQo` |
| Short ID | `32eedaf295ce60a8` |
| Fingerprint | `chrome` |

### VLESS Share Link (Direct REALITY)

```
vless://061527a1-af84-4688-87d1-f08edf0dc8b4@188.166.252.16:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=w7QKHjzAPCl6_V_HlezcQGCe4dkntvOo3JGpc-7tZQo&sid=32eedaf295ce60a8&type=tcp#DIGI-REALITY
```

### Clash.Meta (Direct REALITY)

```yaml
proxies:
  - name: "DIGI-REALITY"
    type: vless
    server: 188.166.252.16
    port: 443
    uuid: 061527a1-af84-4688-87d1-f08edf0dc8b4
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    reality-opts:
      public-key: w7QKHjzAPCl6_V_HlezcQGCe4dkntvOo3JGpc-7tZQo
      short-id: 32eedaf295ce60a8
    client-fingerprint: chrome
```

---

## Option 2: Cloudflare Tunnel (Server IP Hidden)

Connection via Cloudflare CDN. Server IP completely hidden, works even if VPS IP is blocked.

| Setting | Value |
|---------|-------|
| Address | `r.hyas.space` |
| Port | `443` |
| Protocol | VLESS |
| UUID | `061527a1-af84-4688-87d1-f08edf0dc8b4` |
| Network | WebSocket |
| WS Path | `/vless-warp` |
| TLS | `true` |
| SNI | `r.hyas.space` |

### VLESS Share Link (CF Tunnel)

```
vless://061527a1-af84-4688-87d1-f08edf0dc8b4@r.hyas.space:443?encryption=none&security=tls&sni=r.hyas.space&type=ws&path=%2Fvless-warp#DIGI-CF-WARP
```

### Clash.Meta (CF Tunnel)

```yaml
proxies:
  - name: "DIGI-CF-WARP"
    type: vless
    server: r.hyas.space
    port: 443
    uuid: 061527a1-af84-4688-87d1-f08edf0dc8b4
    network: ws
    tls: true
    udp: false
    servername: r.hyas.space
    ws-opts:
      path: /vless-warp
```

### Sing-box (CF Tunnel)

```json
{
  "type": "vless",
  "tag": "digi-cf-warp",
  "server": "r.hyas.space",
  "server_port": 443,
  "uuid": "061527a1-af84-4688-87d1-f08edf0dc8b4",
  "tls": {
    "enabled": true,
    "server_name": "r.hyas.space"
  },
  "transport": {
    "type": "ws",
    "path": "/vless-warp"
  }
}
```

---

## Traffic Flow Comparison

### Direct REALITY
```
Client --> REALITY:443 (looks like microsoft.com) --> VPS --> WARP --> Internet
                                                              ↓
                                                    Clean Cloudflare IP
```

### Cloudflare Tunnel
```
Client --> Cloudflare CDN (r.hyas.space) --> CF Tunnel --> VPS --> WARP --> Internet
              ↓                                                      ↓
        Server IP hidden                                  Clean Cloudflare IP
```

---

## Management

```bash
# Start
cd /allah/blue/linux/vps/digi/xray-reality
docker-compose up -d

# Check logs
docker logs -f xray-reality

# Stop
docker-compose down

# Restart
docker-compose restart
```

## Verify WARP Outbound

After connecting through either proxy option, check your exit IP:

```bash
# Should show Cloudflare IP (104.x.x.x range), not 129.212.209.177
curl https://ifconfig.me
```

## All Proxy Options on This VPS

| Name | Protocol | Address | Port | Notes |
|------|----------|---------|------|-------|
| DIGI-REALITY | VLESS+REALITY | 188.166.252.16 | 443 | Direct, fastest |
| DIGI-CF-WARP | VLESS+WS | r.hyas.space | 443 | Via CF Tunnel |
| x.hyas.space | Trojan+WS | x.hyas.space | 443 | Via CF Tunnel (original) |
| Shadowsocks | SS-AEAD | 188.166.252.16 | 12033 | Direct |
