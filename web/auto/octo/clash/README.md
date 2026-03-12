# Clash Proxy Tools

Utilities for managing Clash proxy nodes and checking IP quality.

## Files

| File | Description |
|------|-------------|
| `ipqs.py` | IP Quality Score API client - fraud detection, VPN/proxy detection |
| `proxy.py` | Clash API client - switch nodes, test delays, batch testing |
| `start.sh` | Launch Clash Nyanpasu GUI |
| `nodes_test.json` | Test results from `test_and_export()` |

## Usage

```python
from clash import switch_to_us, check_ip, show_status

show_status()           # Show current node and available regions
switch_to_us()          # Switch to US IPLC node
check_ip()              # Check current IP reputation
```

## Quick Commands

```python
from clash.proxy import *

switch_to_hk()          # Hong Kong
switch_to_us()          # USA  
switch_to_jp()          # Japan
switch_to_sg()          # Singapore
switch_to_auto()        # Auto select
switch_node("node_name") # Specific node

list_nodes()            # List all nodes
test_and_export()       # Test all nodes, save to JSON
```

## Clash Nyanpasu Install

```
Version: 2.0.0-alpha+ee70ea5
Source: https://github.com/libnyanpasu/clash-nyanpasu/releases/tag/pre-release
Launch: "Clash Nyanpasu" or ./start.sh
```

## Using Tailscale as Upstream Proxy

When using a proxy running on a Tailscale node (e.g., Clash on Windows via Tailscale IP), TUN mode causes routing loops.

### Problem

With TUN mode enabled (`auto-route: true`), traffic to Tailscale IPs (100.64.0.0/10) gets captured by mihomo's TUN interface, creating a routing loop where mihomo tries to connect to the proxy through itself.

### Solution

Add `interface-name: tailscale0` to the proxy config to force mihomo to use the Tailscale interface directly:

```yaml
proxies:
- name: tailscale-proxy
  type: http
  server: 100.116.72.20  # Tailscale IP
  port: 7890
  interface-name: tailscale0  # Key fix - bypass TUN routing
```

### Alternative: Route Exclusion

You can also exclude Tailscale IPs from TUN routing (less reliable with Nyanpasu):

```yaml
tun:
  enable: true
  route-exclude-address:
    - 100.64.0.0/10
```

Note: Nyanpasu regenerates config on restart. Use `interface-name` in the profile for persistence.

### API Commands

```bash
# Check proxy status
curl -H "Authorization: Bearer $SECRET" http://127.0.0.1:$PORT/proxies/tailscale-proxy

# Test proxy delay
curl -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$PORT/proxies/tailscale-proxy/delay?url=http://www.gstatic.com/generate_204&timeout=5000"

# Reload config
curl -X PUT -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$PORT/configs?force=true" -d '{"path": "/path/to/config.yaml"}'

# Enable TUN with route exclusion
curl -X PATCH -H "Authorization: Bearer $SECRET" http://127.0.0.1:$PORT/configs -d '{"tun":{"enable":true,"route-exclude-address":["100.64.0.0/10"]}}'
```

### Config Paths

```
Profile:     /root/.config/clash-nyanpasu/profiles/*.yaml
Active:      /root/.config/clash-nyanpasu/clash-config.yaml
Settings:    /root/.config/clash-nyanpasu/nyanpasu-config.yaml
```
