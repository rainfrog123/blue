# Cloudflare CLI Usage Guide

## Setup

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Credentials

Credentials are automatically loaded from `/allah/blue/cred.json` (no setup needed).

Fallback order:
1. `CLOUDFLARE_API_TOKEN` env var
2. `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` env vars
3. `/allah/blue/cred.json` → `cloudflare.email` + `cloudflare.global_api_key`
4. `/allah/blue/cred.json` → `cloudflare_alt.api_token`

## Commands

### Zones (Domains)

```bash
# List all domains
./cli.py zones list

# Get zone details
./cli.py zones get
./cli.py zones get --zone-id 2c5bc584bd4a638c9b6a36a85dc591cb
```

### DNS Records

```bash
# List DNS records
./cli.py dns list
./cli.py dns list --type A
./cli.py dns list --type CNAME

# Add DNS record
./cli.py dns add --type A --name www --content 1.2.3.4
./cli.py dns add --type A --name api --content 1.2.3.4 --proxied
./cli.py dns add --type CNAME --name mail --content mail.example.com
./cli.py dns add --type MX --name @ --content mail.example.com

# Delete DNS record
./cli.py dns delete <record-id>
```

### Workers

```bash
# List all workers
./cli.py workers list

# Get worker script
./cli.py workers get
./cli.py workers get --name hyas-mail

# Delete worker
./cli.py workers delete <worker-name>

# Tail worker logs (requires wrangler)
./cli.py workers tail --name hyas-mail
```

### KV Namespaces

```bash
# List all KV namespaces
./cli.py kv list

# List keys in namespace
./cli.py kv keys
./cli.py kv keys --prefix "user:"
./cli.py kv keys --limit 50

# Get value
./cli.py kv get mykey

# Put value
./cli.py kv put mykey "myvalue"
./cli.py kv put mykey -              # read from stdin

# Delete key
./cli.py kv delete mykey
```

### D1 Database

```bash
# List all D1 databases
./cli.py d1 list

# Execute SQL query
./cli.py d1 query "SELECT * FROM emails LIMIT 10"
./cli.py d1 query "SELECT COUNT(*) FROM emails"
./cli.py d1 query "SELECT * FROM emails" --json
```

### Email Routing

```bash
# Get email routing status
./cli.py email status

# Enable/disable email routing
./cli.py email enable
./cli.py email disable

# List email rules
./cli.py email rules

# Get catch-all rule
./cli.py email catchall get

# Set catch-all to worker
./cli.py email catchall set --type worker --value hyas-mail

# Set catch-all to forward
./cli.py email catchall set --type forward --value dest@example.com

# Disable catch-all (drop emails)
./cli.py email catchall set --type drop
```

### Cloudflare Tunnels

```bash
# List all tunnels
./cli.py tunnel list

# Create a new tunnel
./cli.py tunnel create my-tunnel

# Get tunnel details
./cli.py tunnel get <tunnel-id>

# Get install token (for VPS)
./cli.py tunnel token <tunnel-id>

# Get/set tunnel ingress config
./cli.py tunnel config get <tunnel-id>
./cli.py tunnel config set <tunnel-id> --hostname x.hyas.site --service http://localhost:10086

# Create DNS CNAME pointing to tunnel
./cli.py tunnel route-dns <tunnel-id> tunnel.hyas.site

# Delete tunnel
./cli.py tunnel delete <tunnel-id>
```

### Custom Hostnames (SSL for SaaS)

```bash
# List all custom hostnames
./cli.py hostname list

# Add a custom hostname
./cli.py hostname add x.hyas.site

# Get custom hostname details
./cli.py hostname get <hostname-id>

# Refresh SSL certificate
./cli.py hostname refresh <hostname-id>

# Delete custom hostname
./cli.py hostname delete <hostname-id>
```

### Fallback Origin

```bash
# Get current fallback origin
./cli.py fallback get

# Set fallback origin
./cli.py fallback set tunnel.hyas.site

# Delete fallback origin
./cli.py fallback delete
```

### One-Click Relay Setup

```bash
# Create full relay: tunnel + DNS + fallback + custom hostname
./cli.py setup relay
./cli.py setup relay --tunnel-name my-relay
./cli.py setup relay \
    --tunnel-name my-relay \
    --tunnel-subdomain tunnel.hyas.site \
    --custom-hostname x.hyas.site

# Teardown relay
./cli.py setup teardown \
    --tunnel-id <tunnel-id> \
    --hostname-id <hostname-id> \
    --dns-record-id <dns-record-id>
```

### One-Click Deploy (Recommended)

```bash
# Deploy new relay with auto-generated VPS files
./deploy.py --name myrelay --hostname x.hyas.space --zone hyas.space

# Custom output directory
./deploy.py --name myrelay --hostname x.hyas.space --zone hyas.space --output /path/to/vps

# Available zones: hyas.site, hyas.space
```

This creates:
- Cloudflare tunnel + DNS + fallback + custom hostname
- `deployments/<name>/docker-compose.yml` - Ready for VPS
- `deployments/<name>/config.json` - Xray config
- `deployments/<name>/client.txt` - Client configs (Clash, Trojan URL)

### Account

```bash
# Show account info
./cli.py account

# Verify API token
./cli.py whoami
```

## Current Domains

| Domain | Zone ID | Status |
|--------|---------|--------|
| hyas.site | `2c5bc584bd4a638c9b6a36a85dc591cb` | active |
| hyas.space | `14a1737c5a43cdff29c09a606c162316` | active |

## Current Relay Setup

| Component | Name | ID | Status |
|-----------|------|-----|--------|
| Tunnel | `x` | `6b2a1433-b8f1-4aa6-86ed-0b4df4013ef3` | healthy |
| Custom Hostname | `x.hyas.site` | `b366b1e4-6a2f-4802-90fc-3d7ebc4fdc10` | SSL active |
| Fallback Origin | `x.hyas.site` | — | active |

See [RELAY_SETUP.md](RELAY_SETUP.md) for detailed architecture documentation.

## Config File

The CLI uses `config.json` for default values:

```json
{
  "account_id": "5d75ad91bc621086a1908973590051c3",
  "zone_id": "2c5bc584bd4a638c9b6a36a85dc591cb",
  "zone_name": "hyas.site",
  "kv_namespace_id": "b7c6dfb18dce4914bc0b93887cc83a9b",
  "d1_database_id": "3a703fbd-0081-4863-abeb-2fab432f78b4",
  "worker_name": "hyas-mail"
}
```

To work with `hyas.space` instead, use `--zone-id 14a1737c5a43cdff29c09a606c162316`.
