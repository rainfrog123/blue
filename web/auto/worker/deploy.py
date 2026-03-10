#!/usr/bin/env python3
"""
Deploy hyas-mail worker to Cloudflare via API
"""

import requests
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "linux" / "extra"))
from cred_loader import get_cloudflare

# Load config
CONFIG_PATH = Path(__file__).parent / "config.json"
with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)


def deploy():
    creds = get_cloudflare()
    
    account_id = CONFIG["account_id"]
    kv_id = CONFIG["kv_namespace_id"]
    d1_id = CONFIG["d1_database_id"]
    worker_name = CONFIG["worker_name"]
    worker_url = CONFIG["worker_url"]
    
    headers = {
        "X-Auth-Email": creds["email"],
        "X-Auth-Key": creds["global_api_key"],
    }

    # Read worker script
    script_path = Path(__file__).parent / f"{worker_name}.js"
    with open(script_path, "r") as f:
        worker_script = f.read()

    # Metadata with bindings
    metadata = {
        "main_module": "worker.js",
        "bindings": [
            {"type": "kv_namespace", "name": "OTP_KV", "namespace_id": kv_id},
            {"type": "d1", "name": "EMAILS_DB", "id": d1_id},
        ],
    }

    # Deploy worker
    print(f"Deploying {worker_name}...")
    files = {
        "metadata": (None, json.dumps(metadata), "application/json"),
        "worker.js": ("worker.js", worker_script, "application/javascript+module"),
    }

    resp = requests.put(
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}",
        headers=headers,
        files=files,
    )

    result = resp.json()
    if result.get("success"):
        print("Deployed successfully!")
        print(f"URL: {worker_url}")
    else:
        print(f"Error: {result.get('errors')}")
        sys.exit(1)


if __name__ == "__main__":
    deploy()
