#!/usr/bin/env python3
"""Azure SOCKS5 Proxy CLI - deploy/manage a SOCKS5 proxy via Azure Container Instances."""
import os
import sys
import argparse
from pathlib import Path

for _parent in Path(__file__).resolve().parents:
    if (_parent / "cred.json").exists():
        sys.path.insert(0, str(_parent / "linux" / "extra"))
        break

from cred_loader import get_azure

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    from azure.mgmt.containerinstance.models import (
        ContainerGroup, Container, ContainerPort, ResourceRequirements,
        ResourceRequests, IpAddress, Port, EnvironmentVariable,
        OperatingSystemTypes,
    )
except ImportError:
    print("Installing Azure SDK...")
    os.system("pip install --break-system-packages azure-identity azure-mgmt-resource azure-mgmt-containerinstance")
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    from azure.mgmt.containerinstance.models import (
        ContainerGroup, Container, ContainerPort, ResourceRequirements,
        ResourceRequests, IpAddress, Port, EnvironmentVariable,
        OperatingSystemTypes,
    )

# ============================================================================
# CONFIGURATION
# ============================================================================
LOCATION = "germanywestcentral"
RESOURCE_GROUP = "socks5-proxy"
CONTAINER_GROUP_NAME = "socks5-de"
IMAGE = "serjs/go-socks5-proxy"
PORT = 1080
CPU = 1.0
MEMORY_GB = 1.5
PROXY_USER = "blue"
PROXY_PASSWORD = "bxsnucrgk6hfish"


def get_clients():
    creds = get_azure()
    credential = ClientSecretCredential(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
    )
    sub_id = creds.get("subscription_id")
    if not sub_id:
        print("No subscription_id in credentials!")
        sys.exit(1)
    resource = ResourceManagementClient(credential, sub_id)
    aci = ContainerInstanceManagementClient(credential, sub_id)
    return resource, aci


def deploy(resource, aci):
    """Create resource group + container instance."""
    print(f"Creating resource group '{RESOURCE_GROUP}' in {LOCATION}...")
    resource.resource_groups.create_or_update(RESOURCE_GROUP, {"location": LOCATION})
    print("  done")

    container = Container(
        name=CONTAINER_GROUP_NAME,
        image=IMAGE,
        resources=ResourceRequirements(
            requests=ResourceRequests(cpu=CPU, memory_in_gb=MEMORY_GB),
        ),
        ports=[ContainerPort(port=PORT, protocol="TCP")],
        environment_variables=[
            EnvironmentVariable(name="PROXY_USER", value=PROXY_USER),
            EnvironmentVariable(name="PROXY_PASSWORD", secure_value=PROXY_PASSWORD),
        ],
    )

    group = ContainerGroup(
        location=LOCATION,
        containers=[container],
        os_type=OperatingSystemTypes.linux,
        ip_address=IpAddress(
            ports=[Port(port=PORT, protocol="TCP")],
            type="Public",
        ),
        restart_policy="Always",
    )

    print(f"Deploying container '{CONTAINER_GROUP_NAME}'...")
    poller = aci.container_groups.begin_create_or_update(
        RESOURCE_GROUP, CONTAINER_GROUP_NAME, group,
    )
    result = poller.result()
    ip = result.ip_address.ip if result.ip_address else "(pending)"
    print(f"  done\n")
    print(f"{'='*50}")
    print(f"  SOCKS5 Proxy Ready")
    print(f"{'='*50}")
    print(f"  Host:     {ip}")
    print(f"  Port:     {PORT}")
    print(f"  User:     {PROXY_USER}")
    print(f"  Password: {PROXY_PASSWORD}")
    print(f"  Type:     SOCKS5")
    print(f"")
    print(f"  curl --socks5-hostname {ip}:{PORT} --proxy-user {PROXY_USER}:{PROXY_PASSWORD} http://ifconfig.me")


def status(resource, aci):
    """Show container group state and IP."""
    try:
        cg = aci.container_groups.get(RESOURCE_GROUP, CONTAINER_GROUP_NAME)
    except Exception:
        print("Container group not found. Run 'deploy' first.")
        return

    ip = cg.ip_address.ip if cg.ip_address else "(none)"
    state = cg.provisioning_state or "Unknown"
    containers = cg.containers or []

    print(f"\n{'='*50}")
    print(f"  SOCKS5 Proxy Status")
    print(f"{'='*50}")
    print(f"  Resource Group: {RESOURCE_GROUP}")
    print(f"  Location:       {cg.location}")
    print(f"  Provisioning:   {state}")
    print(f"  Public IP:      {ip}")
    print(f"  Port:           {PORT}")

    for c in containers:
        istate = c.instance_view
        if istate:
            current = istate.current_state
            print(f"\n  Container: {c.name}")
            print(f"    State:    {current.state if current else 'Unknown'}")
            print(f"    Started:  {current.start_time if current else 'N/A'}")
            print(f"    Restarts: {istate.restart_count}")


def stop(resource, aci):
    """Stop the container group (saves CPU/RAM costs)."""
    print(f"Stopping '{CONTAINER_GROUP_NAME}'...", end=" ", flush=True)
    try:
        aci.container_groups.stop(RESOURCE_GROUP, CONTAINER_GROUP_NAME)
        print("done")
    except Exception as e:
        print(f"failed: {e}")


def start(resource, aci):
    """Start a stopped container group."""
    print(f"Starting '{CONTAINER_GROUP_NAME}'...", end=" ", flush=True)
    try:
        aci.container_groups.start(RESOURCE_GROUP, CONTAINER_GROUP_NAME).result()
        print("done")
        cg = aci.container_groups.get(RESOURCE_GROUP, CONTAINER_GROUP_NAME)
        ip = cg.ip_address.ip if cg.ip_address else "(pending)"
        print(f"  IP: {ip}:{PORT}")
    except Exception as e:
        print(f"failed: {e}")


def delete(resource, aci):
    """Delete the container group and resource group."""
    print(f"Deleting container group '{CONTAINER_GROUP_NAME}'...", end=" ", flush=True)
    try:
        aci.container_groups.begin_delete(RESOURCE_GROUP, CONTAINER_GROUP_NAME).result()
        print("done")
    except Exception:
        print("(not found)")

    print(f"Deleting resource group '{RESOURCE_GROUP}'...", end=" ", flush=True)
    try:
        resource.resource_groups.begin_delete(RESOURCE_GROUP).result()
        print("done")
    except Exception:
        print("(not found)")


def ip_cmd(resource, aci):
    """Print just the public IP."""
    try:
        cg = aci.container_groups.get(RESOURCE_GROUP, CONTAINER_GROUP_NAME)
        ip = cg.ip_address.ip if cg.ip_address else None
        if ip:
            print(ip)
        else:
            print("No IP assigned.")
    except Exception:
        print("Container group not found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Azure SOCKS5 Proxy CLI")
    parser.add_argument(
        "action",
        choices=["deploy", "status", "stop", "start", "delete", "ip"],
        help="deploy | status | stop | start | delete | ip",
    )
    args = parser.parse_args()

    resource_client, aci_client = get_clients()
    actions = {
        "deploy": deploy,
        "status": status,
        "stop": stop,
        "start": start,
        "delete": delete,
        "ip": ip_cmd,
    }
    actions[args.action](resource_client, aci_client)
