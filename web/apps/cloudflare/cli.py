#!/usr/bin/env python3
"""Cloudflare CLI - Manage domains, workers, email routing, and more."""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

# Add cred_loader to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "linux/extra"))
from cred_loader import get_cloudflare

CONFIG_PATH = Path(__file__).parent / "config.json"
API_BASE = "https://api.cloudflare.com/client/v4"


def load_config():
    """Load configuration from config.json."""
    if not CONFIG_PATH.exists():
        print(f"Error: {CONFIG_PATH} not found", file=sys.stderr)
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_headers():
    """Get API headers from cred_loader or environment variables."""
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if token:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    
    email = os.environ.get("CLOUDFLARE_EMAIL")
    api_key = os.environ.get("CLOUDFLARE_API_KEY")
    if email and api_key:
        return {
            "X-Auth-Email": email,
            "X-Auth-Key": api_key,
            "Content-Type": "application/json",
        }
    
    try:
        cf = get_cloudflare()
        if cf.get("api_token"):
            return {
                "Authorization": f"Bearer {cf['api_token']}",
                "Content-Type": "application/json",
            }
        if cf.get("email") and cf.get("global_api_key"):
            return {
                "X-Auth-Email": cf["email"],
                "X-Auth-Key": cf["global_api_key"],
                "Content-Type": "application/json",
            }
    except (FileNotFoundError, KeyError):
        pass
    
    print("Error: No credentials found. Set env vars or check cred.json", file=sys.stderr)
    sys.exit(1)


def api_request(method, endpoint, **kwargs):
    """Make an API request and handle errors."""
    url = f"{API_BASE}{endpoint}"
    headers = get_headers()
    resp = requests.request(method, url, headers=headers, **kwargs)
    data = resp.json()
    
    if not data.get("success", False):
        errors = data.get("errors", [])
        for err in errors:
            print(f"Error: {err.get('message', err)}", file=sys.stderr)
        sys.exit(1)
    
    return data.get("result", data)


# ============================================================================
# ZONES (Domains)
# ============================================================================

def cmd_zones_list(args):
    """List all zones (domains) in the account."""
    result = api_request("GET", "/zones", params={"per_page": 50})
    
    if not result:
        print("No zones found.")
        return
    
    print(f"{'Zone Name':<30} {'Zone ID':<35} {'Status':<10} {'Plan'}")
    print("-" * 90)
    for zone in result:
        print(f"{zone['name']:<30} {zone['id']:<35} {zone['status']:<10} {zone['plan']['name']}")


def cmd_zones_get(args):
    """Get details for a specific zone."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("GET", f"/zones/{zone_id}")
    print(json.dumps(result, indent=2))


# ============================================================================
# DNS Records
# ============================================================================

def cmd_dns_list(args):
    """List DNS records for a zone."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    params = {"per_page": 100}
    if args.type:
        params["type"] = args.type.upper()
    
    result = api_request("GET", f"/zones/{zone_id}/dns_records", params=params)
    
    if not result:
        print("No DNS records found.")
        return
    
    print(f"{'Type':<8} {'Name':<40} {'Content':<45} {'Proxied'}")
    print("-" * 100)
    for rec in result:
        proxied = "Yes" if rec.get("proxied") else "No"
        content = rec["content"][:42] + "..." if len(rec["content"]) > 45 else rec["content"]
        print(f"{rec['type']:<8} {rec['name']:<40} {content:<45} {proxied}")


def cmd_dns_add(args):
    """Add a DNS record."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    data = {
        "type": args.type.upper(),
        "name": args.name,
        "content": args.content,
        "proxied": args.proxied,
    }
    if args.ttl:
        data["ttl"] = args.ttl
    
    result = api_request("POST", f"/zones/{zone_id}/dns_records", json=data)
    print(f"Created DNS record: {result['id']}")


def cmd_dns_delete(args):
    """Delete a DNS record."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    api_request("DELETE", f"/zones/{zone_id}/dns_records/{args.record_id}")
    print(f"Deleted DNS record: {args.record_id}")


# ============================================================================
# Workers
# ============================================================================

def cmd_workers_list(args):
    """List all workers in the account."""
    config = load_config()
    account_id = config.get("account_id")
    
    result = api_request("GET", f"/accounts/{account_id}/workers/scripts")
    
    if not result:
        print("No workers found.")
        return
    
    print(f"{'Worker Name':<30} {'Modified':<25}")
    print("-" * 60)
    for worker in result:
        modified = worker.get("modified_on", "N/A")[:19]
        print(f"{worker['id']:<30} {modified:<25}")


def cmd_workers_get(args):
    """Get worker script content."""
    config = load_config()
    account_id = config.get("account_id")
    name = args.name or config.get("worker_name")
    
    url = f"{API_BASE}/accounts/{account_id}/workers/scripts/{name}"
    headers = get_headers()
    del headers["Content-Type"]
    
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"Error: {resp.status_code} - {resp.text}", file=sys.stderr)
        sys.exit(1)
    
    print(resp.text)


def cmd_workers_delete(args):
    """Delete a worker."""
    config = load_config()
    account_id = config.get("account_id")
    
    api_request("DELETE", f"/accounts/{account_id}/workers/scripts/{args.name}")
    print(f"Deleted worker: {args.name}")


def cmd_workers_tail(args):
    """Get worker logs (requires wrangler for real-time tailing)."""
    config = load_config()
    account_id = config.get("account_id")
    name = args.name or config.get("worker_name")
    
    print(f"To tail logs for '{name}', run:")
    print(f"  npx wrangler tail {name}")


# ============================================================================
# KV Namespaces
# ============================================================================

def cmd_kv_list(args):
    """List all KV namespaces."""
    config = load_config()
    account_id = config.get("account_id")
    
    result = api_request("GET", f"/accounts/{account_id}/storage/kv/namespaces")
    
    if not result:
        print("No KV namespaces found.")
        return
    
    print(f"{'Namespace Title':<30} {'Namespace ID':<35}")
    print("-" * 70)
    for ns in result:
        print(f"{ns['title']:<30} {ns['id']:<35}")


def cmd_kv_keys(args):
    """List keys in a KV namespace."""
    config = load_config()
    account_id = config.get("account_id")
    ns_id = args.namespace_id or config.get("kv_namespace_id")
    
    params = {"limit": args.limit}
    if args.prefix:
        params["prefix"] = args.prefix
    
    result = api_request("GET", f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/keys", params=params)
    
    if not result:
        print("No keys found.")
        return
    
    print(f"{'Key':<60} {'Expiration'}")
    print("-" * 80)
    for key in result:
        exp = key.get("expiration", "Never")
        print(f"{key['name']:<60} {exp}")


def cmd_kv_get(args):
    """Get a value from KV."""
    config = load_config()
    account_id = config.get("account_id")
    ns_id = args.namespace_id or config.get("kv_namespace_id")
    
    url = f"{API_BASE}/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{args.key}"
    headers = get_headers()
    
    resp = requests.get(url, headers=headers)
    if resp.status_code == 404:
        print(f"Key not found: {args.key}", file=sys.stderr)
        sys.exit(1)
    
    print(resp.text)


def cmd_kv_put(args):
    """Put a value into KV."""
    config = load_config()
    account_id = config.get("account_id")
    ns_id = args.namespace_id or config.get("kv_namespace_id")
    
    url = f"{API_BASE}/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{args.key}"
    headers = get_headers()
    headers["Content-Type"] = "text/plain"
    
    value = args.value
    if args.value == "-":
        value = sys.stdin.read()
    
    resp = requests.put(url, headers=headers, data=value)
    if resp.status_code not in (200, 201):
        print(f"Error: {resp.text}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Stored key: {args.key}")


def cmd_kv_delete(args):
    """Delete a key from KV."""
    config = load_config()
    account_id = config.get("account_id")
    ns_id = args.namespace_id or config.get("kv_namespace_id")
    
    api_request("DELETE", f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{args.key}")
    print(f"Deleted key: {args.key}")


# ============================================================================
# D1 Database
# ============================================================================

def cmd_d1_list(args):
    """List all D1 databases."""
    config = load_config()
    account_id = config.get("account_id")
    
    result = api_request("GET", f"/accounts/{account_id}/d1/database")
    
    if not result:
        print("No D1 databases found.")
        return
    
    print(f"{'Database Name':<25} {'Database ID':<40} {'Version'}")
    print("-" * 80)
    for db in result:
        print(f"{db['name']:<25} {db['uuid']:<40} {db.get('version', 'N/A')}")


def cmd_d1_query(args):
    """Execute a SQL query on D1."""
    config = load_config()
    account_id = config.get("account_id")
    db_id = args.database_id or config.get("d1_database_id")
    
    result = api_request(
        "POST",
        f"/accounts/{account_id}/d1/database/{db_id}/query",
        json={"sql": args.sql}
    )
    
    if isinstance(result, list) and result:
        result = result[0]
    
    if result.get("results"):
        if args.json:
            print(json.dumps(result["results"], indent=2))
        else:
            if result["results"]:
                cols = list(result["results"][0].keys())
                print(" | ".join(cols))
                print("-" * (len(" | ".join(cols)) + 5))
                for row in result["results"]:
                    print(" | ".join(str(row.get(c, "")) for c in cols))
    else:
        print(f"Success: {result.get('meta', {})}")


# ============================================================================
# Email Routing
# ============================================================================

def cmd_email_status(args):
    """Get email routing status."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("GET", f"/zones/{zone_id}/email/routing")
    print(json.dumps(result, indent=2))


def cmd_email_enable(args):
    """Enable email routing."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    api_request("POST", f"/zones/{zone_id}/email/routing/enable")
    print("Email routing enabled.")


def cmd_email_disable(args):
    """Disable email routing."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    api_request("POST", f"/zones/{zone_id}/email/routing/disable")
    print("Email routing disabled.")


def cmd_email_rules(args):
    """List email routing rules."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("GET", f"/zones/{zone_id}/email/routing/rules")
    
    if not result:
        print("No email rules found.")
        return
    
    print(f"{'ID':<35} {'Enabled':<8} {'Matchers':<20} {'Actions'}")
    print("-" * 100)
    for rule in result:
        matchers = ", ".join(m.get("type", "?") for m in rule.get("matchers", []))
        actions = ", ".join(f"{a['type']}:{a.get('value', '')}" for a in rule.get("actions", []))
        enabled = "Yes" if rule.get("enabled") else "No"
        print(f"{rule['id']:<35} {enabled:<8} {matchers:<20} {actions}")


def cmd_email_catchall(args):
    """Get or set catch-all email rule."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    if args.action == "get":
        result = api_request("GET", f"/zones/{zone_id}/email/routing/rules/catch_all")
        print(json.dumps(result, indent=2))
    
    elif args.action == "set":
        if not args.type or not args.value:
            print("Error: --type and --value required for 'set'", file=sys.stderr)
            sys.exit(1)
        
        data = {
            "matchers": [{"type": "all"}],
            "actions": [{"type": args.type, "value": [args.value] if args.value else None}],
            "enabled": not args.disable,
            "name": args.name or "Catch-all rule",
        }
        if args.type == "drop":
            data["actions"] = [{"type": "drop"}]
        
        result = api_request("PUT", f"/zones/{zone_id}/email/routing/rules/catch_all", json=data)
        print("Catch-all rule updated:")
        print(json.dumps(result, indent=2))


# ============================================================================
# Cloudflare Tunnels
# ============================================================================

def cmd_tunnel_list(args):
    """List all Cloudflare Tunnels."""
    config = load_config()
    account_id = config.get("account_id")
    
    params = {"is_deleted": "false"}
    result = api_request("GET", f"/accounts/{account_id}/cfd_tunnel", params=params)
    
    if not result:
        print("No tunnels found.")
        return
    
    print(f"{'Name':<25} {'Tunnel ID':<40} {'Status':<12} {'Created'}")
    print("-" * 100)
    for tunnel in result:
        status = "active" if tunnel.get("status") == "active" else tunnel.get("status", "unknown")
        created = tunnel.get("created_at", "N/A")[:10]
        print(f"{tunnel['name']:<25} {tunnel['id']:<40} {status:<12} {created}")


def cmd_tunnel_create(args):
    """Create a new Cloudflare Tunnel."""
    config = load_config()
    account_id = config.get("account_id")
    
    import secrets
    tunnel_secret = secrets.token_bytes(32)
    tunnel_secret_b64 = __import__('base64').b64encode(tunnel_secret).decode()
    
    data = {
        "name": args.name,
        "tunnel_secret": tunnel_secret_b64,
        "config_src": "cloudflare",
    }
    
    result = api_request("POST", f"/accounts/{account_id}/cfd_tunnel", json=data)
    
    print(f"Tunnel created successfully!")
    print(f"  Name: {result['name']}")
    print(f"  ID: {result['id']}")
    print(f"  Created: {result.get('created_at', 'N/A')}")
    print()
    print("Next steps:")
    print(f"  1. Get install token: ./cli.py tunnel token {result['id']}")
    print(f"  2. On VPS, run: cloudflared service install <token>")


def cmd_tunnel_delete(args):
    """Delete a Cloudflare Tunnel."""
    config = load_config()
    account_id = config.get("account_id")
    
    api_request("DELETE", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}")
    print(f"Deleted tunnel: {args.tunnel_id}")


def cmd_tunnel_get(args):
    """Get details for a specific tunnel."""
    config = load_config()
    account_id = config.get("account_id")
    
    result = api_request("GET", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}")
    print(json.dumps(result, indent=2))


def cmd_tunnel_token(args):
    """Get the install token for a tunnel (used by cloudflared)."""
    config = load_config()
    account_id = config.get("account_id")
    
    result = api_request("GET", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}/token")
    
    print("Install token (use this on your VPS):")
    print()
    print(result)
    print()
    print("Install command:")
    print(f"  cloudflared service install {result}")


def cmd_tunnel_config(args):
    """Get or set tunnel ingress configuration."""
    config = load_config()
    account_id = config.get("account_id")
    
    if args.action == "get":
        result = api_request("GET", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}/configurations")
        print(json.dumps(result, indent=2))
    
    elif args.action == "set":
        if not args.hostname or not args.service:
            print("Error: --hostname and --service required for 'set'", file=sys.stderr)
            sys.exit(1)
        
        ingress = [
            {"hostname": args.hostname, "service": args.service},
            {"service": "http_status:404"},
        ]
        
        data = {"config": {"ingress": ingress}}
        result = api_request("PUT", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}/configurations", json=data)
        print("Tunnel configuration updated:")
        print(json.dumps(result, indent=2))


def cmd_tunnel_route_dns(args):
    """Create a DNS CNAME record pointing to the tunnel."""
    config = load_config()
    account_id = config.get("account_id")
    zone_id = args.zone_id or config.get("zone_id")
    
    tunnel_id = args.tunnel_id
    fqdn = args.fqdn
    
    cname_target = f"{tunnel_id}.cfargotunnel.com"
    
    data = {
        "type": "CNAME",
        "name": fqdn,
        "content": cname_target,
        "proxied": True,
    }
    
    result = api_request("POST", f"/zones/{zone_id}/dns_records", json=data)
    print(f"Created DNS route for tunnel:")
    print(f"  {fqdn} -> {cname_target}")
    print(f"  Record ID: {result['id']}")


# ============================================================================
# Custom Hostnames (SSL for SaaS)
# ============================================================================

def cmd_hostname_list(args):
    """List all custom hostnames."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    params = {"per_page": 50}
    result = api_request("GET", f"/zones/{zone_id}/custom_hostnames", params=params)
    
    if not result:
        print("No custom hostnames found.")
        return
    
    print(f"{'Hostname':<35} {'ID':<40} {'SSL Status':<15} {'Created'}")
    print("-" * 110)
    for h in result:
        ssl_status = h.get("ssl", {}).get("status", "unknown")
        created = h.get("created_at", "N/A")[:10]
        print(f"{h['hostname']:<35} {h['id']:<40} {ssl_status:<15} {created}")


def cmd_hostname_add(args):
    """Add a custom hostname (uses fallback origin)."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    data = {
        "hostname": args.hostname,
        "ssl": {
            "method": "http",
            "type": "dv",
            "settings": {
                "min_tls_version": "1.2",
            },
        },
    }
    
    result = api_request("POST", f"/zones/{zone_id}/custom_hostnames", json=data)
    
    print(f"Custom hostname added:")
    print(f"  Hostname: {result['hostname']}")
    print(f"  ID: {result['id']}")
    print(f"  SSL Status: {result.get('ssl', {}).get('status', 'pending')}")
    print()
    print("Note: SSL certificate will be provisioned automatically.")
    print("      Traffic will route to the fallback origin.")


def cmd_hostname_delete(args):
    """Delete a custom hostname."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    api_request("DELETE", f"/zones/{zone_id}/custom_hostnames/{args.hostname_id}")
    print(f"Deleted custom hostname: {args.hostname_id}")


def cmd_hostname_get(args):
    """Get details for a specific custom hostname."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("GET", f"/zones/{zone_id}/custom_hostnames/{args.hostname_id}")
    print(json.dumps(result, indent=2))


def cmd_hostname_refresh(args):
    """Refresh SSL for a custom hostname."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("PATCH", f"/zones/{zone_id}/custom_hostnames/{args.hostname_id}", json={})
    print(f"SSL refresh triggered for: {result['hostname']}")
    print(f"  SSL Status: {result.get('ssl', {}).get('status', 'unknown')}")


# ============================================================================
# Fallback Origin
# ============================================================================

def cmd_fallback_get(args):
    """Get the current fallback origin."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    result = api_request("GET", f"/zones/{zone_id}/custom_hostnames/fallback_origin")
    
    if result.get("origin"):
        print(f"Fallback Origin: {result['origin']}")
        print(f"  Status: {result.get('status', 'unknown')}")
    else:
        print("No fallback origin configured.")


def cmd_fallback_set(args):
    """Set the fallback origin for custom hostnames."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    data = {"origin": args.origin}
    result = api_request("PUT", f"/zones/{zone_id}/custom_hostnames/fallback_origin", json=data)
    
    print(f"Fallback origin set:")
    print(f"  Origin: {result.get('origin', args.origin)}")
    print(f"  Status: {result.get('status', 'pending')}")
    print()
    print("Note: Ensure this hostname has a DNS record (CNAME to tunnel or A record to VPS).")


def cmd_fallback_delete(args):
    """Delete the fallback origin."""
    config = load_config()
    zone_id = args.zone_id or config.get("zone_id")
    
    api_request("DELETE", f"/zones/{zone_id}/custom_hostnames/fallback_origin")
    print("Fallback origin deleted.")


# ============================================================================
# One-Click Setup
# ============================================================================

def cmd_setup_relay(args):
    """One-click setup: Create tunnel + fallback + custom hostname."""
    config = load_config()
    account_id = config.get("account_id")
    zone_id = args.zone_id or config.get("zone_id")
    zone_name = config.get("zone_name", "example.com")
    
    tunnel_name = args.tunnel_name or f"relay-{__import__('secrets').token_hex(4)}"
    tunnel_subdomain = args.tunnel_subdomain or f"tunnel.{zone_name}"
    custom_hostname = args.custom_hostname or f"x.{zone_name}"
    
    print("=" * 60)
    print("Relay Architecture Setup")
    print("=" * 60)
    print()
    
    # Step 1: Create tunnel
    print("[1/4] Creating Cloudflare Tunnel...")
    import secrets as sec
    tunnel_secret = sec.token_bytes(32)
    tunnel_secret_b64 = __import__('base64').b64encode(tunnel_secret).decode()
    
    tunnel_data = {
        "name": tunnel_name,
        "tunnel_secret": tunnel_secret_b64,
        "config_src": "cloudflare",
    }
    tunnel = api_request("POST", f"/accounts/{account_id}/cfd_tunnel", json=tunnel_data)
    tunnel_id = tunnel['id']
    print(f"       Created tunnel: {tunnel_name}")
    print(f"       Tunnel ID: {tunnel_id}")
    
    # Step 2: Create DNS record for tunnel
    print()
    print("[2/4] Creating DNS record for tunnel endpoint...")
    cname_target = f"{tunnel_id}.cfargotunnel.com"
    dns_data = {
        "type": "CNAME",
        "name": tunnel_subdomain,
        "content": cname_target,
        "proxied": True,
    }
    dns_record = api_request("POST", f"/zones/{zone_id}/dns_records", json=dns_data)
    print(f"       {tunnel_subdomain} -> {cname_target}")
    
    # Step 3: Set fallback origin
    print()
    print("[3/4] Setting fallback origin...")
    fallback_data = {"origin": tunnel_subdomain}
    api_request("PUT", f"/zones/{zone_id}/custom_hostnames/fallback_origin", json=fallback_data)
    print(f"       Fallback origin: {tunnel_subdomain}")
    
    # Step 4: Create custom hostname (SNI)
    print()
    print("[4/4] Creating custom hostname (SNI domain)...")
    hostname_data = {
        "hostname": custom_hostname,
        "ssl": {
            "method": "http",
            "type": "dv",
            "settings": {"min_tls_version": "1.2"},
        },
    }
    hostname = api_request("POST", f"/zones/{zone_id}/custom_hostnames", json=hostname_data)
    print(f"       Custom hostname: {custom_hostname}")
    print(f"       SSL Status: {hostname.get('ssl', {}).get('status', 'pending')}")
    
    # Get install token
    print()
    print("=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    
    token = api_request("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token")
    
    print()
    print("TUNNEL INSTALL TOKEN (run on VPS):")
    print("-" * 60)
    print(token)
    print("-" * 60)
    print()
    print("VPS SETUP COMMANDS:")
    print(f"  curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared")
    print(f"  chmod +x /usr/local/bin/cloudflared")
    print(f"  cloudflared service install {token}")
    print()
    print("CLIENT CONFIG:")
    print(f"  server: <preferred-cloudflare-ip>")
    print(f"  sni: {custom_hostname}")
    print(f"  host: {custom_hostname}")
    print()
    print("SUMMARY:")
    print(f"  Tunnel Name:      {tunnel_name}")
    print(f"  Tunnel ID:        {tunnel_id}")
    print(f"  Tunnel Endpoint:  {tunnel_subdomain}")
    print(f"  Custom Hostname:  {custom_hostname}")
    print(f"  Fallback Origin:  {tunnel_subdomain}")


def cmd_setup_teardown(args):
    """Teardown: Delete custom hostname, fallback, tunnel DNS, and tunnel."""
    config = load_config()
    account_id = config.get("account_id")
    zone_id = args.zone_id or config.get("zone_id")
    
    print("=" * 60)
    print("Relay Architecture Teardown")
    print("=" * 60)
    print()
    
    errors = []
    
    # Step 1: Delete custom hostname
    if args.hostname_id:
        print(f"[1/4] Deleting custom hostname {args.hostname_id}...")
        try:
            api_request("DELETE", f"/zones/{zone_id}/custom_hostnames/{args.hostname_id}")
            print("       Deleted.")
        except SystemExit:
            errors.append("custom hostname")
            print("       Failed (may not exist).")
    else:
        print("[1/4] Skipping custom hostname (no --hostname-id provided)")
    
    # Step 2: Delete fallback origin
    print()
    print("[2/4] Deleting fallback origin...")
    try:
        api_request("DELETE", f"/zones/{zone_id}/custom_hostnames/fallback_origin")
        print("       Deleted.")
    except SystemExit:
        errors.append("fallback origin")
        print("       Failed (may not exist).")
    
    # Step 3: Delete DNS record
    if args.dns_record_id:
        print()
        print(f"[3/4] Deleting DNS record {args.dns_record_id}...")
        try:
            api_request("DELETE", f"/zones/{zone_id}/dns_records/{args.dns_record_id}")
            print("       Deleted.")
        except SystemExit:
            errors.append("DNS record")
            print("       Failed (may not exist).")
    else:
        print()
        print("[3/4] Skipping DNS record (no --dns-record-id provided)")
    
    # Step 4: Delete tunnel
    if args.tunnel_id:
        print()
        print(f"[4/4] Deleting tunnel {args.tunnel_id}...")
        try:
            api_request("DELETE", f"/accounts/{account_id}/cfd_tunnel/{args.tunnel_id}")
            print("       Deleted.")
        except SystemExit:
            errors.append("tunnel")
            print("       Failed (tunnel may have active connections).")
    else:
        print()
        print("[4/4] Skipping tunnel (no --tunnel-id provided)")
    
    print()
    print("=" * 60)
    if errors:
        print(f"Teardown completed with errors: {', '.join(errors)}")
    else:
        print("Teardown complete!")
    print("=" * 60)


# ============================================================================
# Account Info
# ============================================================================

def cmd_account_info(args):
    """Get account information."""
    result = api_request("GET", "/accounts", params={"per_page": 10})
    
    for account in result:
        print(f"Account: {account['name']}")
        print(f"  ID: {account['id']}")
        print(f"  Type: {account.get('type', 'N/A')}")


def cmd_whoami(args):
    """Verify API token and show user info."""
    result = api_request("GET", "/user/tokens/verify")
    print(f"Token Status: {result.get('status', 'unknown')}")
    
    user = api_request("GET", "/user")
    print(f"Email: {user.get('email', 'N/A')}")
    print(f"User ID: {user.get('id', 'N/A')}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare CLI - Manage domains, workers, email routing, and more",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # zones
    zones_parser = subparsers.add_parser("zones", help="Manage zones (domains)")
    zones_sub = zones_parser.add_subparsers(dest="subcommand")
    
    zones_sub.add_parser("list", help="List all zones")
    
    zones_get = zones_sub.add_parser("get", help="Get zone details")
    zones_get.add_argument("--zone-id", help="Zone ID (default from config)")
    
    # dns
    dns_parser = subparsers.add_parser("dns", help="Manage DNS records")
    dns_sub = dns_parser.add_subparsers(dest="subcommand")
    
    dns_list = dns_sub.add_parser("list", help="List DNS records")
    dns_list.add_argument("--zone-id", help="Zone ID (default from config)")
    dns_list.add_argument("--type", help="Filter by record type (A, CNAME, MX, etc.)")
    
    dns_add = dns_sub.add_parser("add", help="Add DNS record")
    dns_add.add_argument("--zone-id", help="Zone ID (default from config)")
    dns_add.add_argument("--type", required=True, help="Record type (A, CNAME, MX, etc.)")
    dns_add.add_argument("--name", required=True, help="Record name")
    dns_add.add_argument("--content", required=True, help="Record content")
    dns_add.add_argument("--proxied", action="store_true", help="Enable Cloudflare proxy")
    dns_add.add_argument("--ttl", type=int, help="TTL in seconds")
    
    dns_del = dns_sub.add_parser("delete", help="Delete DNS record")
    dns_del.add_argument("--zone-id", help="Zone ID (default from config)")
    dns_del.add_argument("record_id", help="DNS record ID to delete")
    
    # workers
    workers_parser = subparsers.add_parser("workers", help="Manage Workers")
    workers_sub = workers_parser.add_subparsers(dest="subcommand")
    
    workers_sub.add_parser("list", help="List all workers")
    
    workers_get = workers_sub.add_parser("get", help="Get worker script")
    workers_get.add_argument("--name", help="Worker name (default from config)")
    
    workers_del = workers_sub.add_parser("delete", help="Delete worker")
    workers_del.add_argument("name", help="Worker name to delete")
    
    workers_tail = workers_sub.add_parser("tail", help="Tail worker logs")
    workers_tail.add_argument("--name", help="Worker name (default from config)")
    
    # kv
    kv_parser = subparsers.add_parser("kv", help="Manage KV namespaces")
    kv_sub = kv_parser.add_subparsers(dest="subcommand")
    
    kv_sub.add_parser("list", help="List KV namespaces")
    
    kv_keys = kv_sub.add_parser("keys", help="List keys in namespace")
    kv_keys.add_argument("--namespace-id", help="Namespace ID (default from config)")
    kv_keys.add_argument("--prefix", help="Key prefix filter")
    kv_keys.add_argument("--limit", type=int, default=100, help="Max keys to return")
    
    kv_get = kv_sub.add_parser("get", help="Get value from KV")
    kv_get.add_argument("key", help="Key to get")
    kv_get.add_argument("--namespace-id", help="Namespace ID (default from config)")
    
    kv_put = kv_sub.add_parser("put", help="Put value into KV")
    kv_put.add_argument("key", help="Key to set")
    kv_put.add_argument("value", help="Value to set (use - for stdin)")
    kv_put.add_argument("--namespace-id", help="Namespace ID (default from config)")
    
    kv_del = kv_sub.add_parser("delete", help="Delete key from KV")
    kv_del.add_argument("key", help="Key to delete")
    kv_del.add_argument("--namespace-id", help="Namespace ID (default from config)")
    
    # d1
    d1_parser = subparsers.add_parser("d1", help="Manage D1 databases")
    d1_sub = d1_parser.add_subparsers(dest="subcommand")
    
    d1_sub.add_parser("list", help="List D1 databases")
    
    d1_query = d1_sub.add_parser("query", help="Execute SQL query")
    d1_query.add_argument("sql", help="SQL query to execute")
    d1_query.add_argument("--database-id", help="Database ID (default from config)")
    d1_query.add_argument("--json", action="store_true", help="Output as JSON")
    
    # email
    email_parser = subparsers.add_parser("email", help="Manage email routing")
    email_sub = email_parser.add_subparsers(dest="subcommand")
    
    email_status = email_sub.add_parser("status", help="Get email routing status")
    email_status.add_argument("--zone-id", help="Zone ID (default from config)")
    
    email_enable = email_sub.add_parser("enable", help="Enable email routing")
    email_enable.add_argument("--zone-id", help="Zone ID (default from config)")
    
    email_disable = email_sub.add_parser("disable", help="Disable email routing")
    email_disable.add_argument("--zone-id", help="Zone ID (default from config)")
    
    email_rules = email_sub.add_parser("rules", help="List email rules")
    email_rules.add_argument("--zone-id", help="Zone ID (default from config)")
    
    email_catchall = email_sub.add_parser("catchall", help="Manage catch-all rule")
    email_catchall.add_argument("action", choices=["get", "set"], help="Action to perform")
    email_catchall.add_argument("--zone-id", help="Zone ID (default from config)")
    email_catchall.add_argument("--type", choices=["forward", "worker", "drop"], help="Action type")
    email_catchall.add_argument("--value", help="Action value (email or worker name)")
    email_catchall.add_argument("--name", help="Rule name")
    email_catchall.add_argument("--disable", action="store_true", help="Disable the rule")
    
    # tunnel
    tunnel_parser = subparsers.add_parser("tunnel", help="Manage Cloudflare Tunnels")
    tunnel_sub = tunnel_parser.add_subparsers(dest="subcommand")
    
    tunnel_sub.add_parser("list", help="List all tunnels")
    
    tunnel_create = tunnel_sub.add_parser("create", help="Create a new tunnel")
    tunnel_create.add_argument("name", help="Tunnel name")
    
    tunnel_delete = tunnel_sub.add_parser("delete", help="Delete a tunnel")
    tunnel_delete.add_argument("tunnel_id", help="Tunnel ID to delete")
    
    tunnel_get = tunnel_sub.add_parser("get", help="Get tunnel details")
    tunnel_get.add_argument("tunnel_id", help="Tunnel ID")
    
    tunnel_token = tunnel_sub.add_parser("token", help="Get install token for tunnel")
    tunnel_token.add_argument("tunnel_id", help="Tunnel ID")
    
    tunnel_config = tunnel_sub.add_parser("config", help="Get or set tunnel ingress config")
    tunnel_config.add_argument("action", choices=["get", "set"], help="Action to perform")
    tunnel_config.add_argument("tunnel_id", help="Tunnel ID")
    tunnel_config.add_argument("--hostname", help="Ingress hostname (for set)")
    tunnel_config.add_argument("--service", help="Backend service URL (for set, e.g., http://localhost:10086)")
    
    tunnel_route = tunnel_sub.add_parser("route-dns", help="Create DNS CNAME for tunnel")
    tunnel_route.add_argument("tunnel_id", help="Tunnel ID")
    tunnel_route.add_argument("fqdn", help="FQDN for the DNS record (e.g., tunnel.example.com)")
    tunnel_route.add_argument("--zone-id", help="Zone ID (default from config)")
    
    # hostname (custom hostnames / SSL for SaaS)
    hostname_parser = subparsers.add_parser("hostname", help="Manage custom hostnames (SSL for SaaS)")
    hostname_sub = hostname_parser.add_subparsers(dest="subcommand")
    
    hostname_list = hostname_sub.add_parser("list", help="List all custom hostnames")
    hostname_list.add_argument("--zone-id", help="Zone ID (default from config)")
    
    hostname_add = hostname_sub.add_parser("add", help="Add a custom hostname")
    hostname_add.add_argument("hostname", help="Hostname to add (e.g., x.example.com)")
    hostname_add.add_argument("--zone-id", help="Zone ID (default from config)")
    
    hostname_delete = hostname_sub.add_parser("delete", help="Delete a custom hostname")
    hostname_delete.add_argument("hostname_id", help="Custom hostname ID to delete")
    hostname_delete.add_argument("--zone-id", help="Zone ID (default from config)")
    
    hostname_get = hostname_sub.add_parser("get", help="Get custom hostname details")
    hostname_get.add_argument("hostname_id", help="Custom hostname ID")
    hostname_get.add_argument("--zone-id", help="Zone ID (default from config)")
    
    hostname_refresh = hostname_sub.add_parser("refresh", help="Refresh SSL for hostname")
    hostname_refresh.add_argument("hostname_id", help="Custom hostname ID")
    hostname_refresh.add_argument("--zone-id", help="Zone ID (default from config)")
    
    # fallback (fallback origin for custom hostnames)
    fallback_parser = subparsers.add_parser("fallback", help="Manage fallback origin")
    fallback_sub = fallback_parser.add_subparsers(dest="subcommand")
    
    fallback_get = fallback_sub.add_parser("get", help="Get current fallback origin")
    fallback_get.add_argument("--zone-id", help="Zone ID (default from config)")
    
    fallback_set = fallback_sub.add_parser("set", help="Set fallback origin")
    fallback_set.add_argument("origin", help="Fallback origin hostname (e.g., tunnel.example.com)")
    fallback_set.add_argument("--zone-id", help="Zone ID (default from config)")
    
    fallback_delete = fallback_sub.add_parser("delete", help="Delete fallback origin")
    fallback_delete.add_argument("--zone-id", help="Zone ID (default from config)")
    
    # setup (one-click setup/teardown)
    setup_parser = subparsers.add_parser("setup", help="One-click relay setup/teardown")
    setup_sub = setup_parser.add_subparsers(dest="subcommand")
    
    setup_relay = setup_sub.add_parser("relay", help="Create tunnel + fallback + custom hostname")
    setup_relay.add_argument("--tunnel-name", help="Tunnel name (auto-generated if not set)")
    setup_relay.add_argument("--tunnel-subdomain", help="Tunnel DNS subdomain (e.g., tunnel.example.com)")
    setup_relay.add_argument("--custom-hostname", help="Custom hostname for SNI (e.g., x.example.com)")
    setup_relay.add_argument("--zone-id", help="Zone ID (default from config)")
    
    setup_teardown = setup_sub.add_parser("teardown", help="Delete tunnel + fallback + custom hostname")
    setup_teardown.add_argument("--tunnel-id", help="Tunnel ID to delete")
    setup_teardown.add_argument("--hostname-id", help="Custom hostname ID to delete")
    setup_teardown.add_argument("--dns-record-id", help="DNS record ID to delete")
    setup_teardown.add_argument("--zone-id", help="Zone ID (default from config)")
    
    # account
    subparsers.add_parser("account", help="Show account info")
    subparsers.add_parser("whoami", help="Verify token and show user info")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    commands = {
        ("zones", "list"): cmd_zones_list,
        ("zones", "get"): cmd_zones_get,
        ("zones", None): cmd_zones_list,
        ("dns", "list"): cmd_dns_list,
        ("dns", "add"): cmd_dns_add,
        ("dns", "delete"): cmd_dns_delete,
        ("dns", None): cmd_dns_list,
        ("workers", "list"): cmd_workers_list,
        ("workers", "get"): cmd_workers_get,
        ("workers", "delete"): cmd_workers_delete,
        ("workers", "tail"): cmd_workers_tail,
        ("workers", None): cmd_workers_list,
        ("kv", "list"): cmd_kv_list,
        ("kv", "keys"): cmd_kv_keys,
        ("kv", "get"): cmd_kv_get,
        ("kv", "put"): cmd_kv_put,
        ("kv", "delete"): cmd_kv_delete,
        ("kv", None): cmd_kv_list,
        ("d1", "list"): cmd_d1_list,
        ("d1", "query"): cmd_d1_query,
        ("d1", None): cmd_d1_list,
        ("email", "status"): cmd_email_status,
        ("email", "enable"): cmd_email_enable,
        ("email", "disable"): cmd_email_disable,
        ("email", "rules"): cmd_email_rules,
        ("email", "catchall"): cmd_email_catchall,
        ("email", None): cmd_email_status,
        ("tunnel", "list"): cmd_tunnel_list,
        ("tunnel", "create"): cmd_tunnel_create,
        ("tunnel", "delete"): cmd_tunnel_delete,
        ("tunnel", "get"): cmd_tunnel_get,
        ("tunnel", "token"): cmd_tunnel_token,
        ("tunnel", "config"): cmd_tunnel_config,
        ("tunnel", "route-dns"): cmd_tunnel_route_dns,
        ("tunnel", None): cmd_tunnel_list,
        ("hostname", "list"): cmd_hostname_list,
        ("hostname", "add"): cmd_hostname_add,
        ("hostname", "delete"): cmd_hostname_delete,
        ("hostname", "get"): cmd_hostname_get,
        ("hostname", "refresh"): cmd_hostname_refresh,
        ("hostname", None): cmd_hostname_list,
        ("fallback", "get"): cmd_fallback_get,
        ("fallback", "set"): cmd_fallback_set,
        ("fallback", "delete"): cmd_fallback_delete,
        ("fallback", None): cmd_fallback_get,
        ("setup", "relay"): cmd_setup_relay,
        ("setup", "teardown"): cmd_setup_teardown,
        ("account", None): cmd_account_info,
        ("whoami", None): cmd_whoami,
    }
    
    subcommand = getattr(args, "subcommand", None)
    cmd_func = commands.get((args.command, subcommand))
    
    if cmd_func:
        cmd_func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
