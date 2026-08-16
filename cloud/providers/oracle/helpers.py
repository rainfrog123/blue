"""Oracle Cloud Infrastructure (OCI) helpers - config auth + compute/network ops."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

import oci
from oci.exceptions import ServiceError

DEFAULT_CONFIG = Path.home() / ".oci" / "config"
DEFAULT_PROFILE = "DEFAULT"
DEFAULT_SSH_PUB = Path.home() / ".ssh" / "id_rsa.pub"

# Presets aligned with Obsidian Oracle Trial Machines / Always Free notes
PRESETS = {
    "a1-free": {
        "shape": "VM.Standard.A1.Flex",
        "ocpus": 2.0,
        "memory_in_gbs": 12.0,
        "boot_gb": 50,
        "display_name": "a1-free-tokyo",
    },
    "e4-8x64": {
        "shape": "VM.Standard.E4.Flex",
        "ocpus": 8.0,
        "memory_in_gbs": 64.0,
        "boot_gb": 100,
        "display_name": "e4-trial-8x64",
    },
    "e4-4x128": {
        "shape": "VM.Standard.E4.Flex",
        "ocpus": 4.0,
        "memory_in_gbs": 128.0,
        "boot_gb": 100,
        "display_name": "e4-trial-4x128",
    },
    "a1-32x64": {
        "shape": "VM.Standard.A1.Flex",
        "ocpus": 32.0,
        "memory_in_gbs": 64.0,
        "boot_gb": 100,
        "display_name": "a1-trial-32x64",
    },
}


def load_config(config_file: Optional[str] = None, profile: str = DEFAULT_PROFILE) -> dict:
    """Load OCI config from ~/.oci/config (or OCI_CONFIG_FILE)."""
    path = config_file or os.environ.get("OCI_CONFIG_FILE") or str(DEFAULT_CONFIG)
    cfg = oci.config.from_file(path, profile)
    oci.config.validate_config(cfg)
    return cfg


def get_clients(config: Optional[dict] = None):
    """Return (config, identity, compute, network)."""
    cfg = config or load_config()
    return (
        cfg,
        oci.identity.IdentityClient(cfg),
        oci.core.ComputeClient(cfg),
        oci.core.VirtualNetworkClient(cfg),
    )


def usage_client(config: Optional[dict] = None):
    """Usage / Cost Analysis API client (same ~/.oci/config)."""
    cfg = config or load_config()
    return cfg, oci.usage_api.UsageapiClient(cfg)


def compartment_id(cfg: dict) -> str:
    """Default compartment = tenancy root."""
    return cfg["tenancy"]


def print_header(title: str) -> None:
    print("=" * 70)
    print(title)
    print("=" * 70)


def list_availability_domains(identity, compartment: str) -> list:
    return identity.list_availability_domains(compartment).data


def list_instances(compute, compartment: str, lifecycle_state: Optional[str] = None) -> list:
    kwargs: dict[str, Any] = {"compartment_id": compartment}
    if lifecycle_state:
        kwargs["lifecycle_state"] = lifecycle_state
    return list(oci.pagination.list_call_get_all_results(compute.list_instances, **kwargs).data)


def get_instance(compute, instance_id: str):
    return compute.get_instance(instance_id).data


def resolve_instance(compute, compartment: str, name_or_ocid: str):
    """Resolve by OCID or exact/unique display_name."""
    if name_or_ocid.startswith("ocid1.instance."):
        return get_instance(compute, name_or_ocid)
    matches = [i for i in list_instances(compute, compartment) if i.display_name == name_or_ocid]
    if not matches:
        matches = [
            i
            for i in list_instances(compute, compartment)
            if i.display_name.lower() == name_or_ocid.lower()
        ]
    if not matches:
        raise SystemExit(f"No instance named '{name_or_ocid}'")
    if len(matches) > 1:
        raise SystemExit(f"Multiple instances named '{name_or_ocid}' — use OCID")
    return matches[0]


def list_vnics_for_instance(compute, compartment: str, instance_id: str) -> list:
    attachments = oci.pagination.list_call_get_all_results(
        compute.list_vnic_attachments,
        compartment_id=compartment,
        instance_id=instance_id,
    ).data
    return [a for a in attachments if a.lifecycle_state == "ATTACHED"]


def public_ips_for_instance(compute, network, compartment: str, instance_id: str) -> list[str]:
    ips: list[str] = []
    for att in list_vnics_for_instance(compute, compartment, instance_id):
        if not att.vnic_id:
            continue
        vnic = network.get_vnic(att.vnic_id).data
        if vnic.public_ip:
            ips.append(vnic.public_ip)
        elif vnic.private_ip:
            ips.append(f"priv:{vnic.private_ip}")
    return ips


def list_vcns(network, compartment: str) -> list:
    return list(
        oci.pagination.list_call_get_all_results(
            network.list_vcns, compartment_id=compartment
        ).data
    )


def list_subnets(network, compartment: str, vcn_id: Optional[str] = None) -> list:
    kwargs: dict[str, Any] = {"compartment_id": compartment}
    if vcn_id:
        kwargs["vcn_id"] = vcn_id
    return list(oci.pagination.list_call_get_all_results(network.list_subnets, **kwargs).data)


def pick_subnet(network, compartment: str, subnet_id: Optional[str] = None):
    if subnet_id:
        return network.get_subnet(subnet_id).data
    subnets = [s for s in list_subnets(network, compartment) if s.lifecycle_state == "AVAILABLE"]
    if not subnets:
        raise SystemExit("No subnet found — create a VCN/subnet in Console first")
    # Prefer non-private (has public IP assignment possible)
    publicish = [s for s in subnets if not getattr(s, "prohibit_public_ip_on_vnic", False)]
    return (publicish or subnets)[0]


def latest_ubuntu_image(compute, compartment: str, shape: str, version: str = "22.04"):
    images = oci.pagination.list_call_get_all_results(
        compute.list_images,
        compartment_id=compartment,
        operating_system="Canonical Ubuntu",
        operating_system_version=version,
        shape=shape,
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    if not images:
        raise SystemExit(f"No Ubuntu {version} image for shape {shape}")
    return images[0]


def read_ssh_pub(path: Optional[str] = None) -> str:
    p = Path(path) if path else DEFAULT_SSH_PUB
    if not p.is_file():
        raise SystemExit(f"SSH public key not found: {p}")
    return p.read_text(encoding="utf-8").strip()


def launch_instance(
    compute,
    *,
    compartment: str,
    availability_domain: str,
    shape: str,
    ocpus: float,
    memory_in_gbs: float,
    image_id: str,
    subnet_id: str,
    display_name: str,
    ssh_pub: str,
    boot_gb: int = 50,
    assign_public_ip: bool = True,
):
    details = oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment,
        availability_domain=availability_domain,
        display_name=display_name,
        shape=shape,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=float(ocpus),
            memory_in_gbs=float(memory_in_gbs),
        ),
        source_details=oci.core.models.InstanceSourceViaImageDetails(
            source_type="image",
            image_id=image_id,
            boot_volume_size_in_gbs=int(boot_gb),
        ),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=subnet_id,
            assign_public_ip=assign_public_ip,
        ),
        metadata={"ssh_authorized_keys": ssh_pub},
    )
    return compute.launch_instance(details).data


def launch_with_retry(
    compute,
    launch_kwargs: dict,
    *,
    retries: int = 0,
    sleep_s: int = 60,
):
    """Launch; retry on capacity / rate errors up to `retries` times after the first try."""
    attempt = 0
    while True:
        try:
            return launch_instance(compute, **launch_kwargs)
        except ServiceError as e:
            msg = (e.message or "").lower()
            retryable = (
                e.status in (429, 500)
                or "out of host capacity" in msg
                or "internal error" in msg
            )
            if not retryable or attempt >= retries:
                raise
            attempt += 1
            print(f"  capacity/rate ({e.status}): {e.message}")
            print(f"  sleep {sleep_s}s (retry {attempt}/{retries})")
            time.sleep(sleep_s)


def instance_action(compute, instance_id: str, action: str):
    """action: START | STOP | RESET | SOFTRESET | SOFTSTOP"""
    return compute.instance_action(instance_id, action).data


def terminate_instance(compute, instance_id: str, preserve_boot_volume: bool = False):
    compute.terminate_instance(instance_id, preserve_boot_volume=preserve_boot_volume)


def wait_instance_state(
    compute,
    instance_id: str,
    states: set[str],
    timeout_s: int = 600,
    poll_s: int = 10,
):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        inst = get_instance(compute, instance_id)
        if inst.lifecycle_state in states:
            return inst
        time.sleep(poll_s)
    raise TimeoutError(f"Instance {instance_id} not in {states} within {timeout_s}s")


def tenancy_name(identity, tenancy_id: str) -> str:
    try:
        return identity.get_tenancy(tenancy_id).data.name
    except Exception:
        return tenancy_id
