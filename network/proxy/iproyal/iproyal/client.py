"""
IPRoyal proxy client for making requests through rotating proxies.
"""

from dataclasses import dataclass
from typing import Optional

import requests

from .config import build_proxy_url, generate_session_id, IP_CHECK_API, USER_AGENT


@dataclass
class ProxySession:
    """Represents a proxy session with its metadata."""
    ip: str
    session_id: str
    country: str
    lifetime: str
    proxy_url: str


class IPRoyalClient:
    """
    Client for IPRoyal residential proxy service.
    
    Example:
        client = IPRoyalClient(country="de")
        
        # Single request with rotating IP
        response = client.get("https://example.com")
        
        # Sticky session (same IP)
        with client.session("mysession") as session:
            r1 = session.get("https://example.com/page1")
            r2 = session.get("https://example.com/page2")  # Same IP
    """
    
    def __init__(
        self,
        country: str = "de",
        lifetime: str = "1h",
        timeout: int = 30,
    ):
        self.country = country
        self.lifetime = lifetime
        self.timeout = timeout
    
    def _get_proxy_url(self, session_id: Optional[str] = None) -> str:
        """Build proxy URL for request."""
        return build_proxy_url(
            country=self.country,
            session=session_id,
            lifetime=self.lifetime,
        )
    
    def _make_request(
        self,
        method: str,
        url: str,
        session_id: Optional[str] = None,
        **kwargs,
    ) -> requests.Response:
        """Make a request through the proxy."""
        proxy_url = self._get_proxy_url(session_id=session_id)
        
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
    
    def get_current_ip(self, session_id: Optional[str] = None) -> ProxySession:
        """Get current proxy IP and metadata."""
        if session_id is None:
            session_id = generate_session_id()
        
        proxy_url = self._get_proxy_url(session_id=session_id)
        
        response = requests.get(
            IP_CHECK_API,
            proxies={"http": proxy_url, "https": proxy_url},
            headers={"User-Agent": USER_AGENT},
            timeout=self.timeout,
        )
        data = response.json()
        
        return ProxySession(
            ip=data.get("ip", ""),
            session_id=session_id,
            country=self.country,
            lifetime=self.lifetime,
            proxy_url=proxy_url,
        )
    
    def session(self, session_id: Optional[str] = None) -> "StickySession":
        """
        Create a sticky session context manager.
        
        All requests within the session use the same proxy IP.
        """
        if session_id is None:
            session_id = generate_session_id()
        return StickySession(self, session_id)


class StickySession:
    """Context manager for sticky proxy sessions."""
    
    def __init__(self, client: IPRoyalClient, session_id: str):
        self.client = client
        self.session_id = session_id
    
    def __enter__(self) -> "StickySession":
        return self
    
    def __exit__(self, *args):
        pass
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with sticky session."""
        return self.client._make_request(
            "GET", url, session_id=self.session_id, **kwargs
        )
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with sticky session."""
        return self.client._make_request(
            "POST", url, session_id=self.session_id, **kwargs
        )
    
    def get_ip(self) -> ProxySession:
        """Get the current session's IP."""
        return self.client.get_current_ip(session_id=self.session_id)
