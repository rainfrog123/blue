"""Decodo proxy client — rotating and sticky sessions over HTTP(S) or SOCKS5(h)."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests

from .config import (
    DECODO_IP_API,
    USER_AGENT,
    ProxyConfig,
    build_proxy_url,
    get_proxy_config,
    validate_session_id,
)

_FRUITS = (
    "apple",
    "banana",
    "cherry",
    "grape",
    "kiwi",
    "lemon",
    "mango",
    "orange",
    "peach",
    "plum",
)


@dataclass(frozen=True)
class ExitInfo:
    """Exit IP metadata from ``ip.decodo.com/json``."""

    ip: str
    city: str
    country_code: str
    country_name: str
    isp: str
    session_name: Optional[str]
    proxy_url: str
    port: int


# Back-compat alias
ProxySession = ExitInfo


class DecodoClient:
    """
    Requests through Decodo residential / mobile gateways.

    Example::

        client = DecodoClient(country="gb", protocol="socks5h")
        info = client.get_current_ip(session="apple")

        with client.session("banana") as s:
            r = s.get("https://example.com")
    """

    def __init__(
        self,
        country: str = "gb",
        session_duration: int = 60,
        timeout: int = 45,
        protocol: Optional[str] = None,
        config: Optional[ProxyConfig] = None,
    ):
        self.country = country.lower()
        self.session_duration = session_duration
        self.timeout = timeout
        self.config = config or get_proxy_config()
        self.protocol = (protocol or self.config.protocol or "https").lower()

    def build_url(
        self,
        session: Optional[str] = None,
        port: Optional[int] = None,
    ) -> str:
        return build_proxy_url(
            country=self.country,
            session_duration=self.session_duration,
            session=session,
            port=port,
            protocol=self.protocol,
            config=self.config,
        )

    def _default_port(self, session: Optional[str] = None) -> int:
        if self.protocol.startswith("socks"):
            return self.config.socks_port
        return random.randint(self.config.port_min, self.config.port_max)

    def request(
        self,
        method: str,
        url: str,
        *,
        session: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ) -> requests.Response:
        proxy_url = self.build_url(session=session, port=port)
        kwargs.setdefault("timeout", self.timeout)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("User-Agent", USER_AGENT)
        return requests.request(
            method,
            url,
            headers=headers,
            proxies={"http": proxy_url, "https": proxy_url},
            **kwargs,
        )

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def get_current_ip(
        self,
        session: Optional[str] = None,
        *,
        session_name: Optional[str] = None,
        port: Optional[int] = None,
    ) -> ExitInfo:
        # session_name kept for older call sites
        name = session if session is not None else session_name
        if port is None:
            port = self._default_port(name)
        proxy_url = self.build_url(session=name, port=port)

        response = requests.get(
            DECODO_IP_API,
            proxies={"http": proxy_url, "https": proxy_url},
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        return ExitInfo(
            ip=data.get("proxy", {}).get("ip", ""),
            city=data.get("city", {}).get("name", "Unknown"),
            country_code=data.get("country", {}).get("code", "??"),
            country_name=data.get("country", {}).get("name", "Unknown"),
            isp=data.get("isp", {}).get("isp", ""),
            session_name=name,
            proxy_url=proxy_url,
            port=port,
        )

    def session(self, name: Optional[str] = None) -> "StickySession":
        if name is None:
            name = self.generate_session_name()
        else:
            validate_session_id(name)
        return StickySession(self, name)

    @staticmethod
    def generate_session_name() -> str:
        """Random sticky label: fruit + 5 alnum chars (e.g. ``applek3m9x``)."""
        fruit = random.choice(_FRUITS)
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
        return f"{fruit}{suffix}"


class StickySession:
    """Pin one session id (+ HTTPS port) for the context lifetime."""

    def __init__(self, client: DecodoClient, session_name: str):
        self.client = client
        self.session_name = session_name
        self.port: Optional[int] = None
        self.proxy_url: Optional[str] = None

    def __enter__(self) -> "StickySession":
        self.port = self.client._default_port(self.session_name)
        self.proxy_url = self.client.build_url(session=self.session_name, port=self.port)
        return self

    def __exit__(self, *args) -> None:
        return None

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.client.request(
            "GET", url, session=self.session_name, port=self.port, **kwargs
        )

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.client.request(
            "POST", url, session=self.session_name, port=self.port, **kwargs
        )

    def get_ip(self) -> ExitInfo:
        return self.client.get_current_ip(session=self.session_name, port=self.port)

    def __repr__(self) -> str:
        host = urlparse(self.proxy_url or "").hostname
        return f"<StickySession {self.session_name!r} {host}:{self.port}>"
