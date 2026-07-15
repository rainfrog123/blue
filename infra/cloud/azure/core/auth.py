"""Azure authentication and client factory."""
import sys
from pathlib import Path
from dataclasses import dataclass
from functools import lru_cache

_here = Path(__file__).resolve()
for _parent in _here.parents:
    _scripts = _parent / "infra" / "scripts"
    if (_parent / "cred.json").exists() and (_scripts / "cred_loader.py").exists():
        sys.path.insert(0, str(_scripts))
        break
    if (_parent / "cred_loader.py").exists():
        sys.path.insert(0, str(_parent))
        break

from cred_loader import get_azure

from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.consumption import ConsumptionManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient


@dataclass
class AzureClients:
    """Container for Azure management clients."""
    credential: ClientSecretCredential
    subscription_id: str
    account: str
    compute: ComputeManagementClient
    network: NetworkManagementClient
    resource: ResourceManagementClient
    subscription: SubscriptionClient
    cost: CostManagementClient
    consumption: ConsumptionManagementClient
    container: ContainerInstanceManagementClient


def _normalize_account(account: str) -> str:
    aliases = {"az": "azure", "az2": "azure2", "primary": "azure", "secondary": "azure2"}
    return aliases.get(account, account)


@lru_cache(maxsize=8)
def get_credential(account: str = "azure"):
    """Get Azure credential from cred.json for the given account key."""
    account = _normalize_account(account)
    creds = get_azure(account)
    return ClientSecretCredential(
        tenant_id=creds["tenant_id"],
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
    )


@lru_cache(maxsize=8)
def get_subscription_id(account: str = "azure"):
    """Get subscription ID from cred.json or auto-detect for the account."""
    account = _normalize_account(account)
    creds = get_azure(account)
    sub_id = (creds.get("subscription_id") or "").strip()
    if not sub_id:
        credential = get_credential(account)
        subs = list(SubscriptionClient(credential).subscriptions.list())
        sub_id = subs[0].subscription_id if subs else None
    if not sub_id:
        raise RuntimeError(
            f"No Azure subscription for account '{account}'. "
            "Set subscription_id in cred.json or grant the app access to a subscription."
        )
    return sub_id


@lru_cache(maxsize=8)
def get_clients(account: str = "azure") -> AzureClients:
    """Get all Azure management clients for the given cred.json account key."""
    account = _normalize_account(account)
    credential = get_credential(account)
    sub_id = get_subscription_id(account)

    return AzureClients(
        credential=credential,
        subscription_id=sub_id,
        account=account,
        compute=ComputeManagementClient(credential, sub_id),
        network=NetworkManagementClient(credential, sub_id),
        resource=ResourceManagementClient(credential, sub_id),
        subscription=SubscriptionClient(credential),
        cost=CostManagementClient(credential),
        consumption=ConsumptionManagementClient(credential, sub_id),
        container=ContainerInstanceManagementClient(credential, sub_id),
    )
