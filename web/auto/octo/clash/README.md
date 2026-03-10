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
