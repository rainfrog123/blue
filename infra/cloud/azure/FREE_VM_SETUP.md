# Completely Free Azure VM Setup Guide

## Overview

This guide creates a **$0/month** Azure VM using:
- **Standard_B2ats_v2**: 2 vCPUs, 1 GB RAM (AMD x64) - 750 free hours/month
- **64 GB P6 Premium SSD** - free tier eligible
- **Public IPv6 only** - free (no public IPv4)

## Prerequisites

- Azure account with free tier benefits active
- Your network must support IPv6 for SSH access

### Check IPv6 Support

Run this on your local machine before proceeding:

```bash
curl -6 https://ifconfig.co
```

If it returns an IPv6 address, you're good. If it fails, consider the Cloudflare Tunnel alternative at the end.

---

## Step 1: Create Resource Group

```
Name: free-vm-rg
Region: Choose from available regions (see list below)
```

### Regions with B2ats_v2 Availability

| Americas | Europe | Asia-Pacific |
|----------|--------|--------------|
| East US | West Europe | Southeast Asia |
| East US 2 | North Europe | East Asia |
| West US 2 | UK South | Australia East |
| Central US | France Central | Japan East |
| Canada Central | Germany West Central | Korea Central |

---

## Step 2: Create Virtual Network with IPv6

### Subnet Configuration

| Setting | Value |
|---------|-------|
| VNet Name | `free-vm-vnet` |
| IPv4 Address Space | `10.0.0.0/16` |
| IPv6 Address Space | Add one (Azure will assign) |
| Subnet Name | `default` |
| Subnet IPv4 | `10.0.0.0/24` |
| Subnet IPv6 | `/64` (required size) |

---

## Step 3: Create Public IPv6 Address

| Setting | Value |
|---------|-------|
| Name | `free-vm-ipv6` |
| IP Version | **IPv6** |
| SKU | Standard |
| Tier | Regional |
| Assignment | Static |

**Cost: $0** (IPv6 is free)

---

## Step 4: Create Virtual Machine

### Basics Tab

| Setting | Value |
|---------|-------|
| VM Name | `free-vm` |
| Region | Same as resource group |
| Image | Ubuntu Server 24.04 LTS - x64 Gen2 |
| Size | **Standard_B2ats_v2** (2 vCPUs, 1 GB RAM) |
| Authentication | SSH public key (recommended) |
| Username | Your choice |

### Disks Tab

| Setting | Value |
|---------|-------|
| OS Disk Size | **64 GB** (critical - not 128 GB default) |
| OS Disk Type | Premium SSD (P6) |
| Delete with VM | Yes |

### Networking Tab

| Setting | Value |
|---------|-------|
| Virtual Network | `free-vm-vnet` |
| Subnet | `default` |
| Public IP | **None** (we'll attach IPv6 later) |
| NIC NSG | Basic |
| Public inbound ports | Allow SSH (22) |
| Delete NIC on VM delete | Yes |

---

## Step 5: Attach IPv6 to NIC

After VM creation:

1. Go to VM > Networking > Network Interface
2. Click on the NIC name
3. Go to **IP configurations**
4. Click on `ipconfig1`
5. Add IPv6:
   - IPv6: **Enabled**
   - Public IPv6 address: Select `free-vm-ipv6`
6. Save

The VM now has:
- Private IPv4: `10.0.x.x` (required by Azure)
- Public IPv6: `2603:xxxx:xxxx:xxxx::x` (free)
- No public IPv4 (saves $3.65/month)

---

## Step 6: Connect via SSH

```bash
ssh -6 username@2603:xxxx:xxxx:xxxx::x
```

Or in SSH config:

```
Host free-vm
    HostName 2603:xxxx:xxxx:xxxx::x
    User username
    AddressFamily inet6
```

---

## Step 7: Create Swap File (Important)

B2ats_v2 has only 1 GB RAM and no temp disk. Create swap to prevent crashes:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

Verify:

```bash
free -h
# Should show 2G swap
```

---

## Step 8: Set Budget Alert

Create a $0.01 budget alert in Cost Management to catch any accidental charges.

---

## Cost Summary

| Resource | Monthly Cost |
|----------|-------------|
| VM (B2ats_v2, 750 hrs) | $0 |
| OS Disk (64 GB P6) | $0 |
| Public IPv6 | $0 |
| Bandwidth (100 GB egress) | $0 |
| **Total** | **$0** |

---

## Limitations of IPv6-Only

| Works | May Not Work |
|-------|--------------|
| SSH from IPv6 networks | IPv4-only networks (hotels, some offices) |
| apt/dnf package managers | Some IPv4-only APIs |
| Git (GitHub, GitLab) | Legacy services |
| Most modern websites | Some older services |

---

## Alternative: Cloudflare Tunnel (No Public IP)

If IPv6 doesn't work for you, use Cloudflare Tunnel:

1. Create VM with no public IP at all
2. Install cloudflared:

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/
```

3. Authenticate and create tunnel:

```bash
cloudflared tunnel login
cloudflared tunnel create free-vm
cloudflared tunnel route dns free-vm ssh.yourdomain.com
```

4. Connect via:

```bash
cloudflared access ssh --hostname ssh.yourdomain.com
```

This method works from any network (IPv4 or IPv6) and costs $0.

---

## Maintenance

### Deallocate When Not in Use

Simply stopping the OS doesn't stop billing. Use Azure Portal "Stop" button to deallocate:

```bash
# Or via CLI
az vm deallocate --resource-group free-vm-rg --name free-vm
```

### Monitor Free Tier Usage

- 750 hours/month = 31.25 days continuous
- Running 2 VMs = 375 hours each = 15.6 days before charges
- Check usage in Cost Management + Billing

---

## Troubleshooting

### Can't SSH via IPv6

1. Check your local IPv6: `curl -6 https://ifconfig.co`
2. Check NSG allows port 22 for IPv6
3. Verify IPv6 is attached to NIC

### VM Runs Out of Memory

1. Check swap is active: `free -h`
2. If swap not showing, re-run swap setup commands
3. Consider running fewer services

### Quota Errors for B2ats_v2

Try different regions. Some regions have quota issues:
- Best: East US, West Europe, Southeast Asia
- Check: VM > Size > "See all sizes" > Filter "B2ats"

---

*Last updated: April 2026*
