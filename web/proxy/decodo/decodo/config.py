"""Decodo credentials, constants, and proxy URL builder.

Credentials come from ``infra/scripts/cred_loader.get_proxy_decodo()``
(``blue/cred.json`` → ``proxy.decodo``). Env vars still override.
"""

from __future__ import annotations

import os
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, unquote

DECODO_IP_API = "https://ip.decodo.com/json"
GATE_HOST = "gate.decodo.com"
SOCKS_PORT = 10000
HTTPS_PORT_MIN = 30001
HTTPS_PORT_MAX = 50000
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

SUPPORTED_PROTOCOLS = ("http", "https", "socks5", "socks5h")

# Session id is an opaque sticky label (digits, fruit names, uuid hex, ...).
# Avoid characters that break URL auth or Decodo's `-`-joined username params.
_SESSION_SAFE = re.compile(r"^[A-Za-z0-9_]+$")


def _ensure_cred_loader() -> None:
    scripts = Path(__file__).resolve().parents[4] / "infra" / "scripts"
    scripts_str = str(scripts)
    if scripts_str not in sys.path:
        sys.path.insert(0, scripts_str)


def _proxy_block() -> dict[str, Any]:
    _ensure_cred_loader()
    from cred_loader import get_proxy_decodo

    return dict(get_proxy_decodo())


@dataclass(frozen=True)
class ProxyConfig:
    username: str = ""
    password: str = ""
    protocol: str = "socks5h"
    api_key: str = ""
    host: str = GATE_HOST
    port_min: int = HTTPS_PORT_MIN
    port_max: int = HTTPS_PORT_MAX
    socks_port: int = SOCKS_PORT


@dataclass(frozen=True)
class IPQSConfig:
    api_key: str = ""
    base_url: str = "https://ipqualityscore.com/api/json/ip"
    strictness: int = 1


def get_proxy_config() -> ProxyConfig:
    """Load Decodo proxy settings via cred_loader (+ env overrides).

    Protocol is not stored in cred.json — pass it per call / CLI
    (``socks5h``, ``https``, …). Env ``DECODO_PROTOCOL`` still works
    as a process-wide default when set.
    """
    block = _proxy_block()

    username = os.environ.get("DECODO_USERNAME") or block.get("username", "")
    password = os.environ.get("DECODO_PASSWORD") or block.get("password", "")
    # Prefer explicit env; otherwise leave empty so callers/CLI pick a protocol.
    protocol = (os.environ.get("DECODO_PROTOCOL") or "").lower()
    api_key = os.environ.get("DECODO_API_KEY") or block.get("api_key", "")

    return ProxyConfig(
        username=username or "",
        password=password or "",
        protocol=protocol or "socks5h",
        api_key=api_key or "",
    )


def get_decodo_api_key() -> str:
    """Public / management API key from ``proxy.decodo.api_key``."""
    key = get_proxy_config().api_key
    if not key:
        raise ValueError("proxy.decodo.api_key missing in cred.json")
    return key


def get_ipqs_config() -> IPQSConfig:
    """IPQS key via cred_loader.get_ipqs()."""
    _ensure_cred_loader()
    from cred_loader import get_ipqs

    api_key = os.environ.get("IPQS_API_KEY") or get_ipqs()
    return IPQSConfig(api_key=api_key or "")


def validate_session_id(session: str) -> str:
    """Raise if session id is empty or unsafe for Decodo username params."""
    if not session:
        raise ValueError("session id must be non-empty")
    if not _SESSION_SAFE.match(session):
        raise ValueError(
            "session id must be alphanumeric/underscore only "
            f"(no : @ / - spaces); got {session!r}"
        )
    return session


def build_proxy_url(
    country: Optional[str] = None,
    session_duration: int = 60,
    session: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    host: Optional[str] = None,
    *,
    config: Optional[ProxyConfig] = None,
) -> str:
    """
    Build a Decodo proxy URL.

    Username shape (``-`` joined)::

        user-{user}-session-{id}-sessionduration-{mins}-country-{cc}

    ``session`` is an opaque sticky label — numbers, fruit names, uuid hex,
    etc. Same id within ``session_duration`` keeps the same exit IP.

    Defaults:
      - SOCKS → ``gate.decodo.com:10000``
      - HTTP(S) → ``{cc}.decodo.com`` + random sticky port in 30001–50000
    """
    cfg = config or get_proxy_config()
    proto = (protocol or cfg.protocol or "socks5h").lower()
    if proto not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"protocol must be one of {SUPPORTED_PROTOCOLS}, got {proto!r}")

    username = cfg.username.removeprefix("user-")
    if not username or not cfg.password:
        raise ValueError("Decodo username/password missing (cred.json or env)")

    parts = [f"user-{username}"]
    if session is not None:
        parts.append(f"session-{validate_session_id(session)}")
    parts.append(f"sessionduration-{session_duration}")
    if country:
        parts.append(f"country-{country.lower()}")

    auth_user = "-".join(parts)
    auth_pass = quote(cfg.password, safe="")

    is_socks = proto.startswith("socks")
    if host:
        proxy_host = host
    elif is_socks:
        proxy_host = GATE_HOST
    elif country:
        proxy_host = f"{country.lower()}.decodo.com"
    else:
        proxy_host = GATE_HOST

    if port is None:
        if is_socks:
            port = cfg.socks_port
        else:
            port = random.randint(cfg.port_min, cfg.port_max)

    return f"{proto}://{auth_user}:{auth_pass}@{proxy_host}:{port}"


def parse_proxy_url(url: str) -> dict[str, Any]:
    """Split a proxy URL into host/port/user/pass (pass is URL-decoded)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"invalid proxy URL: {url!r}")
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
    }
