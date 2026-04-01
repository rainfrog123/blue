# DigitalOcean Reserved IP for Cleaner Outbound Traffic

## Problem

DigitalOcean droplet IPs are heavily flagged by fraud detection services:

| IP | IPQS Score | Flags |
|----|------------|-------|
| 188.166.252.16 (droplet) | 100/100 | Proxy, VPN, Bot, Recent Abuse |

Datacenter IPs are automatically flagged because:
- They're registered to cloud providers (DigitalOcean, AWS, etc.)
- Many are used for bots, scrapers, and malicious activity
- Fraud databases maintain blocklists of datacenter IP ranges

## Solution: Reserved IP

Reserved IPs (formerly "Floating IPs") are separate IP addresses that can be assigned to droplets. They often have cleaner reputation because:
- They're from different IP blocks
- Less historical abuse associated with them
- Can be rotated/replaced if flagged

### Creating and Testing Reserved IPs

```bash
# Create reserved IP
python cli.py ip-create -r sgp1

# Check IPQS score
python /allah/blue/web/proxy/decodo/cli.py check <ip>

# List reserved IPs
python cli.py ips
```

We created 4 reserved IPs and tested them:

| IP | IPQS Score | Bot | Abuse |
|----|------------|-----|-------|
| 129.212.209.177 | 75 | No | No |
| 165.245.144.168 | 75 | No | No |
| 139.59.216.67 | 75 | No | No |
| 188.166.199.14 | 75 | No | No |

All reserved IPs scored 75 vs the droplet's 100 - 25 points better.

## How Reserved IPs Work

```
┌─────────────────────────────────────────────────────────────┐
│                    DigitalOcean Infrastructure              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Internet                                                  │
│      │                                                      │
│      ▼                                                      │
│   ┌─────────────────┐                                       │
│   │  Reserved IP    │  129.212.209.177                      │
│   │  (Public)       │                                       │
│   └────────┬────────┘                                       │
│            │                                                │
│            │  1:1 NAT at hypervisor level                   │
│            │                                                │
│            ▼                                                │
│   ┌─────────────────┐                                       │
│   │  Anchor IP      │  10.15.0.5 (private)                  │
│   │  (Internal)     │                                       │
│   └────────┬────────┘                                       │
│            │                                                │
│            ▼                                                │
│   ┌─────────────────┐                                       │
│   │    Droplet      │  eth0: 188.166.252.16 (native)        │
│   │     (sg1)       │        10.15.0.5 (anchor)             │
│   └─────────────────┘                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Concepts

1. **Reserved IP**: Public IP (129.212.209.177) that can be moved between droplets
2. **Anchor IP**: Private IP (10.15.0.5) assigned to the droplet, linked to reserved IP via NAT
3. **Anchor Gateway**: Router (10.15.0.1) that performs the NAT translation

### Default Behavior (Problem)

By default:
- **Inbound**: Traffic to reserved IP → NAT → reaches droplet ✅
- **Outbound**: Droplet uses native IP (188.166.252.16) ❌

```bash
# Before fix - outbound uses native IP
$ curl ipinfo.io/ip
188.166.252.16  # Bad IP (score 100)
```

### The Fix

Route outbound traffic through the anchor gateway instead of the regular gateway:

```bash
# Change default route to use anchor gateway
ip route replace default via 10.15.0.1 dev eth0 src 10.15.0.5
```

Now:
- **Outbound**: Droplet → Anchor Gateway (10.15.0.1) → NAT → Reserved IP (129.212.209.177)

```bash
# After fix - outbound uses reserved IP
$ curl ipinfo.io/ip
129.212.209.177  # Cleaner IP (score 75)
```

### Why This Works

1. **Anchor IP (10.15.0.5)** is a private IP that DigitalOcean's hypervisor recognizes
2. **Anchor Gateway (10.15.0.1)** is a special router that performs 1:1 NAT
3. When traffic exits via anchor gateway with anchor IP as source:
   - Hypervisor intercepts the packet
   - Translates source from 10.15.0.5 → 129.212.209.177
   - Sends to internet with reserved IP as source
4. Return traffic to 129.212.209.177 is reverse-NAT'd back to the droplet

### Making It Permanent

Edit `/etc/netplan/50-cloud-init.yaml`:

```yaml
# Change this:
routes:
  - to: "0.0.0.0/0"
    via: "188.166.240.1"    # Regular gateway

# To this:
routes:
  - to: "0.0.0.0/0"
    via: "10.15.0.1"        # Anchor gateway
```

Apply:
```bash
netplan apply
```

## Getting Metadata

DigitalOcean provides metadata about anchor IPs:

```bash
# Anchor IP address
curl http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/address
# Output: 10.15.0.5

# Anchor gateway
curl http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/gateway
# Output: 10.15.0.1

# Reserved IP
curl http://169.254.169.254/metadata/v1/reserved_ip/ipv4/ip_address
# Output: 129.212.209.177
```

## CLI Commands Reference

```bash
# List reserved IPs
python cli.py ips

# Create reserved IP (unassigned, $5/month)
python cli.py ip-create -r sgp1

# Create and assign to droplet (free)
python cli.py ip-create -d <droplet_id>

# Assign existing IP to droplet
python cli.py ip-assign <ip> <droplet_id>

# Unassign IP from droplet
python cli.py ip-unassign <ip>

# Delete reserved IP
python cli.py ip-delete <ip>
```

## Cost

| Status | Cost |
|--------|------|
| Reserved IP assigned to droplet | **Free** |
| Reserved IP unassigned | **$5/month** |

## Results

| Metric | Before | After |
|--------|--------|-------|
| Outbound IP | 188.166.252.16 | 129.212.209.177 |
| IPQS Score | 100 (Critical) | 75 (Critical) |
| Bot Flag | Yes | No |
| Recent Abuse | Yes | No |

Still flagged as datacenter/proxy (unavoidable for cloud IPs), but cleaner history.

## Limitations

- Reserved IPs are still DigitalOcean datacenter IPs
- They will still be flagged as "hosting" by most detection services
- For truly "clean" residential IPs, use residential proxy services (like Decodo)
- Score can degrade over time if the IP gets abused
