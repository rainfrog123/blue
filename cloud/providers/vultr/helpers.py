"""Vultr API helper functions (v2)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests

BASE_URL = "https://api.vultr.com/v2"

ROOT_PATH = Path(__file__).resolve().parents[3]  # blue/
EXTRA_PATH = ROOT_PATH / "workstation" / "scripts"
if str(EXTRA_PATH) not in sys.path:
    sys.path.insert(0, str(EXTRA_PATH))

from cred_loader import get_vultr  # noqa: E402


class VultrAPIError(RuntimeError):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"Vultr API {status}: {body[:500]}")


def load_token() -> str:
    """Load token from VULTR_API_KEY env, else cred.json."""
    env = os.environ.get("VULTR_API_KEY", "").strip()
    if env:
        return env
    return get_vultr()["token"]


def get_headers(token: Optional[str] = None) -> dict:
    if token is None:
        token = load_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _request(
    method: str,
    endpoint: str,
    *,
    token: Optional[str] = None,
    params: Optional[dict] = None,
    json_body: Optional[dict] = None,
) -> Any:
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    resp = requests.request(
        method,
        url,
        headers=get_headers(token),
        params=params,
        json=json_body,
        timeout=60,
    )
    if resp.status_code >= 400:
        raise VultrAPIError(resp.status_code, resp.text)
    if resp.status_code == 204 or not resp.content:
        return None
    return resp.json()


def api_get(endpoint: str, token: Optional[str] = None, params: Optional[dict] = None) -> dict:
    return _request("GET", endpoint, token=token, params=params)


def api_post(endpoint: str, data: dict, token: Optional[str] = None) -> dict:
    return _request("POST", endpoint, token=token, json_body=data)


def api_delete(endpoint: str, token: Optional[str] = None) -> None:
    _request("DELETE", endpoint, token=token)


def api_get_all(endpoint: str, list_key: str, token: Optional[str] = None, params: Optional[dict] = None) -> list:
    """Paginate cursor-style Vultr list endpoints."""
    out: list = []
    cursor = None
    base_params = dict(params or {})
    while True:
        p = dict(base_params)
        if cursor:
            p["cursor"] = cursor
        data = api_get(endpoint, token=token, params=p)
        out.extend(data.get(list_key) or [])
        meta = (data.get("meta") or {}).get("links") or {}
        nxt = meta.get("next")
        if not nxt:
            break
        # next may be a full query string or cursor value
        if "cursor=" in str(nxt):
            cursor = str(nxt).split("cursor=", 1)[1].split("&", 1)[0]
        else:
            cursor = nxt
    return out


# --- Account ---

def get_account() -> dict:
    return api_get("account")["account"]


# --- Instances ---

def list_instances() -> list:
    return api_get_all("instances", "instances")


def get_instance(instance_id: str) -> dict:
    return api_get(f"instances/{instance_id}")["instance"]


def create_instance(**kwargs) -> dict:
    return api_post("instances", kwargs)["instance"]


def delete_instance(instance_id: str) -> None:
    api_delete(f"instances/{instance_id}")


def wait_for_instance(instance_id: str, timeout: int = 300, interval: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        inst = get_instance(instance_id)
        if inst.get("status") == "active" and inst.get("server_status") in ("ok", "none", None):
            # server_status can lag; active + main_ip is enough
            if inst.get("main_ip") and inst["main_ip"] not in ("0.0.0.0", ""):
                return inst
        if inst.get("status") == "active" and inst.get("main_ip") and inst["main_ip"] != "0.0.0.0":
            return inst
        time.sleep(interval)
    raise TimeoutError(f"Instance {instance_id} not ready after {timeout}s")


def instance_ip(inst: dict) -> str:
    return inst.get("main_ip") or "N/A"


# --- Regions / plans / keys ---

def list_regions() -> list:
    return api_get_all("regions", "regions")


def list_plans(params: Optional[dict] = None) -> list:
    return api_get_all("plans", "plans", params=params)


def list_ssh_keys() -> list:
    return api_get_all("ssh-keys", "ssh_keys")
