"""
Decodo proxy client for making requests through rotating proxies.
"""

import random
import string
from dataclasses import dataclass
from typing import Optional

import requests

from .config import build_proxy_url, get_proxy_config, DECODO_IP_API, USER_AGENT


@dataclass
class ProxySession:
    """Represents a proxy session with its metadata."""
    ip: str
    city: str
    country_code: str
    country_name: str
    session_name: Optional[str]
    proxy_url: str
    port: int


class DecodoClient:
    """
    Client for Decodo residential proxy service.
    
    Example:
        client = DecodoClient(country="gb")
        
        # Single request with rotating IP
        response = client.get("https://example.com")
        
        # Sticky session (same IP)
        with client.session("mysession") as session:
            r1 = session.get("https://example.com/page1")
            r2 = session.get("https://example.com/page2")  # Same IP
    """
    
    def __init__(
        self,
        country: str = "gb",
        session_duration: int = 60,
        timeout: int = 30,
    ):
        self.country = country
        self.session_duration = session_duration
        self.timeout = timeout
        self.config = get_proxy_config()
    
    def _get_proxy_url(self, session: Optional[str] = None, port: Optional[int] = None) -> str:
        """Build proxy URL for request."""
        return build_proxy_url(
            country=self.country,
            session_duration=self.session_duration,
            session=session,
            port=port,
        )
    
    def _make_request(
        self,
        method: str,
        url: str,
        session_name: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ) -> requests.Response:
        """Make a request through the proxy."""
        proxy_url = self._get_proxy_url(session=session_name, port=port)
        
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("headers", {})
        kwargs["headers"].setdefault("User-Agent", USER_AGENT)
        kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}
        
        return requests.request(method, url, **kwargs)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request through rotating proxy."""
        return self._make_request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request through rotating proxy."""
        return self._make_request("POST", url, **kwargs)
    
    def get_current_ip(self, session_name: Optional[str] = None) -> ProxySession:
        """Get current proxy IP and metadata."""
        port = random.randint(self.config.port_min, self.config.port_max)
        proxy_url = self._get_proxy_url(session=session_name, port=port)
        
        response = requests.get(
            DECODO_IP_API,
            proxies={"http": proxy_url, "https": proxy_url},
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
        )
        data = response.json()
        
        return ProxySession(
            ip=data.get("proxy", {}).get("ip", ""),
            city=data.get("city", {}).get("name", "Unknown"),
            country_code=data.get("country", {}).get("code", "??"),
            country_name=data.get("country", {}).get("name", "Unknown"),
            session_name=session_name,
            proxy_url=proxy_url,
            port=port,
        )
    
    def session(self, name: Optional[str] = None) -> "StickySession":
        """
        Create a sticky session context manager.
        
        All requests within the session use the same proxy IP.
        """
        if name is None:
            name = self._generate_session_name()
        return StickySession(self, name)
    
    @staticmethod
    def _generate_session_name() -> str:
        """Generate a random session name."""
        fruits = ["apple", "banana", "orange", "grape", "kiwi", "mango", "peach", "cherry"]
        fruit = random.choice(fruits)
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
        return f"{fruit}{suffix}"


class StickySession:
    """Context manager for sticky proxy sessions."""
    
    def __init__(self, client: DecodoClient, session_name: str):
        self.client = client
        self.session_name = session_name
        self._port: Optional[int] = None
    
    def __enter__(self) -> "StickySession":
        # Get a random port and stick with it
        self._port = random.randint(
            self.client.config.port_min,
            self.client.config.port_max,
        )
        return self
    
    def __exit__(self, *args):
        pass
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with sticky session."""
        return self.client._make_request(
            "GET", url, session_name=self.session_name, port=self._port, **kwargs
        )
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with sticky session."""
        return self.client._make_request(
            "POST", url, session_name=self.session_name, port=self._port, **kwargs
        )
    
    def get_ip(self) -> ProxySession:
        """Get the current session's IP."""
        return self.client.get_current_ip(session_name=self.session_name)
