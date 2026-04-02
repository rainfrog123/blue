"""Azure authentication and client factory."""
import sys
from pathlib import Path
from dataclasses import dataclass
from functools import lru_cache

for _parent in Path(__file__).resolve().parents:
    if (_parent / "cred.json").exists():
        sys.path.insert(0, str(_parent / "linux" / "extra"))
        break

from cred_loader import get_azure

from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient


@dataclass
class AzureClients:
    """Container for Azure management clients."""
    credential: ClientSecretCredential
    subscription_id: str
    compute: ComputeManagementClient
    network: NetworkManagementClient
    resource: ResourceManagementClient
    subscription: SubscriptionClient
    cost: CostManagementClient
    container: ContainerInstanceManagementClient


@lru_cache(maxsize=1)
def get_credential():
    """Get Azure credential from cred.json."""
    creds = get_azure()
    return ClientSecretCredential(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"]
    )


@lru_cache(maxsize=1)
def get_subscription_id():
    """Get subscription ID from cred.json or auto-detect."""
    creds = get_azure()
    sub_id = creds.get("subscription_id")
    if not sub_id:
        credential = get_credential()
        subs = list(SubscriptionClient(credential).subscriptions.list())
        sub_id = subs[0].subscription_id if subs else None
    if not sub_id:
        raise RuntimeError("No Azure subscription found")
    return sub_id


@lru_cache(maxsize=1)
def get_clients() -> AzureClients:
    """Get all Azure management clients."""
    credential = get_credential()
    sub_id = get_subscription_id()
    
    return AzureClients(
        credential=credential,
        subscription_id=sub_id,
        compute=ComputeManagementClient(credential, sub_id),
        network=NetworkManagementClient(credential, sub_id),
        resource=ResourceManagementClient(credential, sub_id),
        subscription=SubscriptionClient(credential),
        cost=CostManagementClient(credential),
        container=ContainerInstanceManagementClient(credential, sub_id),
    )
