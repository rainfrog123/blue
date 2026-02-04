# Shadowsocks Server Configuration

## Server Details
- **Server IP**: 47.86.7.159
- **Port**: 443
- **Method**: chacha20-ietf-poly1305
- **Password**: bb553795-6a8f-493c-960c-12a6f2f65eee
- **Mode**: TCP and UDP

## Container Info
- **Container Name**: ss-rust
- **Image**: teddysun/shadowsocks-rust:latest
- **Status**: Running with auto-restart enabled

## Configuration File
Located at: `/etc/shadowsocks-rust/config.json`

## Client Configuration (Clash Format)
```yaml
- name: '🇭🇰SS|HongKongA01|IPLC x3'
  type: ss
  server: 47.86.7.159
  port: 443
  cipher: chacha20-ietf-poly1305
  password: bb553795-6a8f-493c-960c-12a6f2f65eee
```

## Management Commands
```bash
# Check status
docker ps | grep ss-rust

# View logs
docker logs ss-rust

# Restart container
docker restart ss-rust

# Stop container
docker stop ss-rust

# Start container
docker start ss-rust

# Remove container
docker stop ss-rust && docker rm ss-rust
```

## Firewall Status
- UFW Status: **Inactive** (no restrictions)
- iptables: Docker automatically configured rules for port 443
- Both TCP and UDP traffic allowed

## Testing from Windows (PowerShell)
```powershell
# Test ping
Test-Connection -ComputerName 47.86.7.159 -Count 4

# Test port 443
Test-NetConnection -ComputerName 47.86.7.159 -Port 443
```

Expected output: `TcpTestSucceeded : True`

## Notes
- Container auto-restarts on system reboot
- Both TCP and UDP traffic supported
- No firewall blocking required (UFW inactive)
- Port 443 used for better compatibility (appears as HTTPS traffic)