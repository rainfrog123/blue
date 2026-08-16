# DigitalOcean Droplet Options

## Available Regions

| Slug | Location |
|------|----------|
| `nyc1` | New York 1 |
| `nyc2` | New York 2 |
| `nyc3` | New York 3 |
| `sgp1` | Singapore 1 |
| `lon1` | London 1 |
| `ams3` | Amsterdam 3 |
| `fra1` | Frankfurt 1 |
| `tor1` | Toronto 1 |
| `sfo2` | San Francisco 2 |
| `sfo3` | San Francisco 3 |
| `blr1` | Bangalore 1 |
| `syd1` | Sydney 1 |
| `atl1` | Atlanta 1 |
| `ric1` | Richmond 1 |

## Available Sizes (sorted by price)

| Slug | vCPU | RAM | Disk | Transfer | Price |
|------|------|-----|------|----------|-------|
| `s-1vcpu-512mb-10gb` | 1 | 512MB | 10GB | 0.5TB | $4/mo |
| `s-1vcpu-1gb` | 1 | 1GB | 25GB | 1TB | $6/mo |
| `s-1vcpu-1gb-intel` | 1 | 1GB | 25GB | 1TB | $7/mo |
| `s-1vcpu-1gb-35gb-intel` | 1 | 1GB | 35GB | 1TB | $8/mo |
| `s-1vcpu-2gb` | 1 | 2GB | 50GB | 2TB | $12/mo |
| `s-1vcpu-2gb-intel` | 1 | 2GB | 50GB | 2TB | $14/mo |
| `s-1vcpu-2gb-70gb-intel` | 1 | 2GB | 70GB | 2TB | $16/mo |
| `s-2vcpu-2gb` | 2 | 2GB | 60GB | 3TB | $18/mo |
| `s-2vcpu-2gb-intel` | 2 | 2GB | 60GB | 3TB | $21/mo |
| `s-2vcpu-2gb-90gb-intel` | 2 | 2GB | 90GB | 3TB | $24/mo |
| `s-2vcpu-4gb` | 2 | 4GB | 80GB | 4TB | $24/mo |
| `s-2vcpu-4gb-intel` | 2 | 4GB | 80GB | 4TB | $28/mo |
| `s-2vcpu-4gb-120gb-intel` | 2 | 4GB | 120GB | 4TB | $32/mo |
| `c-2` | 2 | 4GB | 25GB | 4TB | $42/mo |
| `s-2vcpu-8gb-160gb-intel` | 2 | 8GB | 160GB | 5TB | $48/mo |
| `s-4vcpu-8gb` | 4 | 8GB | 160GB | 5TB | $48/mo |
| `s-4vcpu-8gb-intel` | 4 | 8GB | 160GB | 5TB | $56/mo |
| `g-2vcpu-8gb` | 2 | 8GB | 25GB | 4TB | $63/mo |
| `s-4vcpu-8gb-240gb-intel` | 4 | 8GB | 240GB | 6TB | $64/mo |
| `gd-2vcpu-8gb` | 2 | 8GB | 50GB | 4TB | $68/mo |

## Size Categories

- **s-** : Shared CPU (Basic)
- **c-** : Dedicated CPU (CPU-Optimized)
- **g-** : Dedicated CPU (General Purpose)
- **gd-** : Dedicated CPU (General Purpose with NVMe SSD)
- **intel** : Intel processor variant

## Quick Reference

**Cheapest option:** `s-1vcpu-512mb-10gb` at $4/mo  
**Default region:** `sgp1` (Singapore)  
**Default size:** `s-1vcpu-512mb-10gb`

### Create droplet example:
```bash
python cli.py create myserver -r sgp1 -s s-1vcpu-1gb
```
