"""IPQualityScore (IPQS) fraud scoring."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import requests

from .config import USER_AGENT, get_ipqs_config


def _risk_level(score: int) -> str:
    if score == 0:
        return "EXCELLENT"
    if score < 20:
        return "LOW"
    if score < 40:
        return "MODERATE"
    if score < 70:
        return "HIGH"
    return "CRITICAL"


def _emoji(score: int) -> str:
    if score == 0:
        return "✅✅✅"
    if score < 20:
        return "✅✅"
    if score < 40:
        return "✅"
    if score < 70:
        return "⚠️"
    return "🚨"


@dataclass(frozen=True)
class IPQSResult:
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
    clean_threshold: int = 50

    @property
    def is_clean(self) -> bool:
        return self.fraud_score < self.clean_threshold

    @property
    def emoji(self) -> str:
        return _emoji(self.fraud_score)


class IPQSChecker:
    """Thin wrapper around IPQS IP reputation API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 15,
        clean_threshold: int = 50,
    ):
        cfg = get_ipqs_config()
        self.api_key = api_key or cfg.api_key
        self.base_url = cfg.base_url
        self.strictness = cfg.strictness
        self.timeout = timeout
        self.clean_threshold = clean_threshold
        if not self.api_key:
            raise ValueError("IPQS api key missing (cred.json ipqs.default_key or IPQS_API_KEY)")

    def check(self, ip: str) -> IPQSResult:
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

        score = int(data.get("fraud_score", 0))
        return IPQSResult(
            ip=ip,
            fraud_score=score,
            country_code=data.get("country_code", "??"),
            city=data.get("city", "Unknown"),
            isp=data.get("ISP", "Unknown"),
            is_proxy=bool(data.get("proxy", False)),
            is_vpn=bool(data.get("vpn", False)),
            is_tor=bool(data.get("tor", False)),
            is_bot=bool(data.get("bot_status", False)),
            recent_abuse=bool(data.get("recent_abuse", False)),
            risk_level=_risk_level(score),
            clean_threshold=self.clean_threshold,
        )

    def check_batch(self, ips: list[str], delay: float = 0.1) -> list[IPQSResult]:
        results: list[IPQSResult] = []
        for ip in ips:
            results.append(self.check(ip))
            time.sleep(delay)
        return results
