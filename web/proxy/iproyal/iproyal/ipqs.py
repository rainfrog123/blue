"""
IPQualityScore (IPQS) API client for IP fraud scoring.
"""

from dataclasses import dataclass
from typing import Optional

import requests

from .config import get_ipqs_config, USER_AGENT


@dataclass
class IPQSResult:
    """IPQS fraud check result."""
    ip: str
    fraud_score: int
    country_code: str
    city: str
    isp: str
    is_proxy: bool
    is_vpn: bool
    is_tor: bool
    is_bot: bool
    recent_abuse: bool
    risk_level: str
    
    @property
    def is_clean(self) -> bool:
        """Check if IP is considered clean (score < 50)."""
        return self.fraud_score < 50
    
    @property
    def emoji(self) -> str:
        """Get emoji representation of fraud score."""
        if self.fraud_score == 0:
            return "✅✅✅"
        elif self.fraud_score < 20:
            return "✅✅"
        elif self.fraud_score < 40:
            return "✅"
        elif self.fraud_score < 70:
            return "⚠️"
        else:
            return "🚨"


class IPQSChecker:
    """
    IPQS fraud score checker.
    
    Example:
        checker = IPQSChecker()
        result = checker.check("8.8.8.8")
        print(f"Score: {result.fraud_score}, Clean: {result.is_clean}")
    """
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 15):
        config = get_ipqs_config()
        self.api_key = api_key or config.api_key
        self.base_url = config.base_url
        self.strictness = config.strictness
        self.timeout = timeout
    
    def check(self, ip: str) -> IPQSResult:
        """
        Check IP address for fraud score and risk indicators.
        
        Args:
            ip: IP address to check (IPv4 or IPv6)
            
        Returns:
            IPQSResult with fraud score and risk indicators
        """
        url = f"{self.base_url}/{self.api_key}/{ip}"
        
        response = requests.get(
            url,
            params={
                "strictness": self.strictness,
                "user_agent": USER_AGENT,
                "user_language": "en-US",
            },
            timeout=self.timeout,
        )
        
        data = response.json()
        
        if not data.get("success"):
            raise ValueError(f"IPQS API error: {data.get('message', 'Unknown error')}")
        
        fraud_score = data.get("fraud_score", 0)
        
        # Determine risk level
        if fraud_score == 0:
            risk_level = "EXCELLENT"
        elif fraud_score < 20:
            risk_level = "LOW"
        elif fraud_score < 40:
            risk_level = "MODERATE"
        elif fraud_score < 70:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return IPQSResult(
            ip=ip,
            fraud_score=fraud_score,
            country_code=data.get("country_code", "??"),
            city=data.get("city", "Unknown"),
            isp=data.get("ISP", "Unknown"),
            is_proxy=data.get("proxy", False),
            is_vpn=data.get("vpn", False),
            is_tor=data.get("tor", False),
            is_bot=data.get("bot_status", False),
            recent_abuse=data.get("recent_abuse", False),
            risk_level=risk_level,
        )
    
    def check_batch(self, ips: list[str], delay: float = 0.1) -> list[IPQSResult]:
        """
        Check multiple IPs with rate limiting.
        
        Args:
            ips: List of IP addresses to check
            delay: Delay between requests (rate limiting)
            
        Returns:
            List of IPQSResult objects
        """
        import time
        
        results = []
        for ip in ips:
            try:
                result = self.check(ip)
                results.append(result)
            except Exception as e:
                print(f"Error checking {ip}: {e}")
            time.sleep(delay)
        
        return results
