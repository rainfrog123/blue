#!/usr/bin/env python3
"""One-click relay deployment: Creates tunnel, configures Cloudflare, generates VPS files."""

import argparse
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "linux/extra"))
from cred_loader import get_cloudflare

CONFIG_PATH = Path(__file__).parent / "config.json"
TEMPLATES_PATH = Path(__file__).parent / "templates"
API_BASE = "https://api.cloudflare.com/client/v4"

# Zone IDs
ZONES = {
    "hyas.site": "2c5bc584bd4a638c9b6a36a85dc591cb",
    "hyas.space": "14a1737c5a43cdff29c09a606c162316",
}


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_headers():
    cf = get_cloudflare()
    if cf.get("api_token"):
        return {"Authorization": f"Bearer {cf['api_token']}", "Content-Type": "application/json"}
    return {
        "X-Auth-Email": cf["email"],
        "X-Auth-Key": cf["global_api_key"],
        "Content-Type": "application/json",
    }


def api_request(method, endpoint, **kwargs):
    url = f"{API_BASE}{endpoint}"
    resp = requests.request(method, url, headers=get_headers(), **kwargs)
    data = resp.json()
    if not data.get("success", False):
        errors = data.get("errors", [])
        for err in errors:
            print(f"Error: {err.get('message', err)}", file=sys.stderr)
        sys.exit(1)
    return data.get("result", data)


def generate_credentials():
    """Generate password and WebSocket path."""
    password = str(uuid.uuid4())
    ws_path = secrets.token_hex(5)
    return password, ws_path


def deploy_relay(tunnel_name: str, hostname: str, zone: str, output_dir: Path):
    """Deploy a complete relay setup."""
    config = load_config()
    account_id = config["account_id"]
    zone_id = ZONES.get(zone)
    
    if not zone_id:
        print(f"Error: Unknown zone '{zone}'. Available: {list(ZONES.keys())}")
        sys.exit(1)
    
    password, ws_path = generate_credentials()
    
    print("=" * 60)
    print(f"Deploying Relay: {hostname}")
    print("=" * 60)
    print()
    
    # Step 1: Create tunnel
    print("[1/6] Creating Cloudflare Tunnel...")
    tunnel_secret = secrets.token_bytes(32)
    tunnel_secret_b64 = __import__('base64').b64encode(tunnel_secret).decode()
    
    tunnel = api_request("POST", f"/accounts/{account_id}/cfd_tunnel", json={
        "name": tunnel_name,
        "tunnel_secret": tunnel_secret_b64,
        "config_src": "cloudflare",
    })
    tunnel_id = tunnel["id"]
    print(f"       Tunnel: {tunnel_name} ({tunnel_id})")
    
    # Step 2: Create DNS CNAME
    print("[2/6] Creating DNS CNAME...")
    cname_target = f"{tunnel_id}.cfargotunnel.com"
    dns = api_request("POST", f"/zones/{zone_id}/dns_records", json={
        "type": "CNAME",
        "name": hostname,
        "content": cname_target,
        "proxied": True,
    })
    print(f"       {hostname} → {cname_target}")
    
    # Step 3: Set fallback origin
    print("[3/6] Setting fallback origin...")
    api_request("PUT", f"/zones/{zone_id}/custom_hostnames/fallback_origin", json={"origin": hostname})
    print(f"       Fallback: {hostname}")
    
    # Step 4: Create custom hostname
    print("[4/6] Creating custom hostname...")
    ch = api_request("POST", f"/zones/{zone_id}/custom_hostnames", json={
        "hostname": hostname,
        "ssl": {"method": "http", "type": "dv", "settings": {"min_tls_version": "1.2"}},
    })
    hostname_id = ch["id"]
    print(f"       Custom Hostname: {hostname} ({hostname_id})")
    
    # Step 5: Configure tunnel ingress
    print("[5/6] Configuring tunnel ingress...")
    api_request("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", json={
        "config": {
            "ingress": [
                {"hostname": hostname, "service": "http://xray-trojan:8080"},
                {"service": "http_status:404"},
            ]
        }
    })
    print(f"       Ingress: {hostname} → http://xray-trojan:8080")
    
    # Step 6: Get tunnel token
    print("[6/6] Getting tunnel token...")
    token = api_request("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token")
    print("       Token retrieved.")
    
    # Generate output files
    print()
    print("=" * 60)
    print("Generating VPS files...")
    print("=" * 60)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # docker-compose.yml
    docker_compose = f"""version: "3.8"

services:
  xray-trojan:
    image: ghcr.io/xtls/xray-core:latest
    container_name: xray-trojan
    restart: always
    volumes:
      - ./config.json:/etc/xray/config.json
    command: run -c /etc/xray/config.json
    networks:
      - tunnel-net

  cloudflared:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    restart: always
    command: tunnel --no-autoupdate run --token {token}
    networks:
      - tunnel-net
    depends_on:
      - xray-trojan

networks:
  tunnel-net:
    driver: bridge
"""
    (output_dir / "docker-compose.yml").write_text(docker_compose)
    print(f"       Created: {output_dir}/docker-compose.yml")
    
    # config.json
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": 8080,
            "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {
                "clients": [{"password": password, "email": f"user@{hostname}"}]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": f"/{ws_path}"}
            }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }
    (output_dir / "config.json").write_text(json.dumps(xray_config, indent=2))
    print(f"       Created: {output_dir}/config.json")
    
    # client.txt
    client_config = f"""# Relay Configuration
# Generated: {__import__('datetime').datetime.now().isoformat()}

## Connection Details
| Setting   | Value |
|-----------|-------|
| Hostname  | {hostname} |
| Port      | 443 |
| Password  | {password} |
| WS Path   | /{ws_path} |
| Tunnel ID | {tunnel_id} |
| Hostname ID | {hostname_id} |

## Trojan URL
trojan://{password}@{hostname}:443?security=tls&type=ws&path=%2F{ws_path}#{tunnel_name}

## Clash (Basic)
- {{name: '{tunnel_name}', type: trojan, server: {hostname}, port: 443, password: {password}, udp: true, sni: {hostname}, skip-cert-verify: false, network: ws, ws-opts: {{path: /{ws_path}}}}}

## Clash (With Preferred IP)
- name: '{tunnel_name}_优选'
  type: trojan
  server: 162.159.25.200
  port: 443
  password: {password}
  udp: true
  sni: {hostname}
  skip-cert-verify: false
  network: ws
  ws-opts:
    path: /{ws_path}
    headers:
      Host: {hostname}

## VPS Deployment
cd {output_dir}
docker-compose up -d
docker-compose logs -f
"""
    (output_dir / "client.txt").write_text(client_config)
    print(f"       Created: {output_dir}/client.txt")
    
    # Summary
    print()
    print("=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)
    print()
    print(f"Tunnel Name:     {tunnel_name}")
    print(f"Tunnel ID:       {tunnel_id}")
    print(f"Hostname:        {hostname}")
    print(f"Password:        {password}")
    print(f"WS Path:         /{ws_path}")
    print()
    print("Next Steps:")
    print(f"  1. Copy {output_dir} to your VPS")
    print(f"  2. Run: docker-compose up -d")
    print(f"  3. Check status: ./cli.py tunnel list")
    print()
    print("Client config saved to:", output_dir / "client.txt")
    
    return {
        "tunnel_id": tunnel_id,
        "tunnel_name": tunnel_name,
        "hostname": hostname,
        "hostname_id": hostname_id,
        "password": password,
        "ws_path": ws_path,
        "token": token,
    }


def main():
    parser = argparse.ArgumentParser(description="One-click relay deployment")
    parser.add_argument("--name", required=True, help="Tunnel name (e.g., 'ali', 'digi')")
    parser.add_argument("--hostname", required=True, help="Custom hostname (e.g., 'x.hyas.space')")
    parser.add_argument("--zone", required=True, choices=list(ZONES.keys()), help="Cloudflare zone")
    parser.add_argument("--output", default=None, help="Output directory for VPS files")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output) if args.output else Path(__file__).parent / "deployments" / args.name
    
    deploy_relay(args.name, args.hostname, args.zone, output_dir)


if __name__ == "__main__":
    main()
