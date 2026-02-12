"""
Session scanner for testing multiple proxy sessions and scoring IPs.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from .client import DecodoClient, ProxySession
from .ipqs import IPQSChecker, IPQSResult


@dataclass
class ScanResult:
    """Result of scanning a proxy session."""
    session: ProxySession
    ipqs: Optional[IPQSResult] = None
    error: Optional[str] = None
    
    @property
    def is_clean(self) -> bool:
        """Check if IP is clean (IPQS score < 50)."""
        return self.ipqs is not None and self.ipqs.is_clean


@dataclass
class ScanSummary:
    """Summary of a scan operation."""
    total_sessions: int
    unique_ips: int
    duplicates: int
    failures: int
    clean_ips: int
    results: list[ScanResult] = field(default_factory=list)
    
    @property
    def best_result(self) -> Optional[ScanResult]:
        """Get the result with lowest fraud score."""
        clean_results = [r for r in self.results if r.is_clean]
        if not clean_results:
            return None
        return min(clean_results, key=lambda r: r.ipqs.fraud_score)


class SessionScanner:
    """
    Scans multiple proxy sessions to find clean IPs.
    
    Example:
        scanner = SessionScanner(country="gb", num_sessions=10)
        summary = scanner.scan()
        
        print(f"Found {summary.clean_ips} clean IPs")
        if summary.best_result:
            print(f"Best IP: {summary.best_result.session.ip}")
            print(f"Proxy URL: {summary.best_result.session.proxy_url}")
    """
    
    def __init__(
        self,
        country: str = "gb",
        num_sessions: int = 10,
        session_duration: int = 60,
        clean_threshold: int = 50,
        max_workers: int = 10,
        timeout: int = 30,
    ):
        self.country = country
        self.num_sessions = num_sessions
        self.session_duration = session_duration
        self.clean_threshold = clean_threshold
        self.max_workers = max_workers
        self.timeout = timeout
        
        self.client = DecodoClient(
            country=country,
            session_duration=session_duration,
            timeout=timeout,
        )
        self.ipqs = IPQSChecker(timeout=15)
    
    def _test_session(self, session_num: int) -> tuple[Optional[ProxySession], Optional[str]]:
        """Test a single proxy session."""
        session_name = f"scan{session_num}"
        try:
            session = self.client.get_current_ip(session_name=session_name)
            return session, None
        except Exception as e:
            return None, str(e)
    
    def _check_ip(self, ip: str) -> tuple[Optional[IPQSResult], Optional[str]]:
        """Check IP with IPQS."""
        try:
            result = self.ipqs.check(ip)
            return result, None
        except Exception as e:
            return None, str(e)
    
    def scan(self, verbose: bool = True) -> ScanSummary:
        """
        Scan multiple proxy sessions and check IPs.
        
        Args:
            verbose: Print progress to stdout
            
        Returns:
            ScanSummary with all results
        """
        if verbose:
            print(f"{'=' * 50}")
            print(f"Decodo Session Scanner")
            print(f"{'=' * 50}")
            print(f"Country: {self.country.upper()}")
            print(f"Sessions: {self.num_sessions}")
            print(f"Duration: {self.session_duration} min")
            print(f"{'=' * 50}")
        
        # Phase 1: Collect IPs
        if verbose:
            print(f"\n[Phase 1] Testing {self.num_sessions} proxy sessions...")
        
        sessions: list[ProxySession] = []
        seen_ips: set[str] = set()
        duplicates = 0
        failures = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._test_session, i): i
                for i in range(1, self.num_sessions + 1)
            }
            
            for future in as_completed(futures):
                session_num = futures[future]
                session, error = future.result()
                
                if error:
                    failures += 1
                    if verbose:
                        print(f"  ✗ session{session_num}: {error[:50]}")
                elif session:
                    if session.ip in seen_ips:
                        duplicates += 1
                        if verbose:
                            print(f"  ⚡ session{session_num}: {session.ip} (duplicate)")
                    else:
                        seen_ips.add(session.ip)
                        sessions.append(session)
                        if verbose:
                            print(f"  ✓ session{session_num}: {session.ip} ({session.city})")
        
        if verbose:
            print(f"\nUnique: {len(sessions)} | Duplicates: {duplicates} | Failures: {failures}")
        
        if not sessions:
            return ScanSummary(
                total_sessions=self.num_sessions,
                unique_ips=0,
                duplicates=duplicates,
                failures=failures,
                clean_ips=0,
            )
        
        # Phase 2: Check IPQS scores
        if verbose:
            print(f"\n[Phase 2] Checking {len(sessions)} IPs with IPQS...")
        
        results: list[ScanResult] = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._check_ip, s.ip): s
                for s in sessions
            }
            
            for future in as_completed(futures):
                session = futures[future]
                ipqs_result, error = future.result()
                
                result = ScanResult(session=session, ipqs=ipqs_result, error=error)
                results.append(result)
                
                if verbose:
                    if error:
                        print(f"  ✗ {session.ip}: {error[:50]}")
                    elif ipqs_result:
                        print(f"  {ipqs_result.emoji} {session.ip}: Score {ipqs_result.fraud_score} ({session.city})")
        
        # Sort by fraud score
        results.sort(key=lambda r: r.ipqs.fraud_score if r.ipqs else 999)
        clean_count = sum(1 for r in results if r.is_clean)
        
        # Phase 3: Summary
        if verbose:
            print(f"\n{'=' * 50}")
            print(f"Clean IPs (Score < {self.clean_threshold})")
            print(f"{'=' * 50}")
            
            for result in results:
                if result.is_clean:
                    print(f"\n{result.ipqs.emoji} Score: {result.ipqs.fraud_score}")
                    print(f"   IP: {result.session.ip}")
                    print(f"   City: {result.session.city}")
                    print(f"   URL: {result.session.proxy_url}")
            
            if results and results[0].is_clean:
                print(f"\n{'=' * 50}")
                print(f"Best Proxy (Score: {results[0].ipqs.fraud_score})")
                print(f"{'=' * 50}")
                print(results[0].session.proxy_url)
            
            print(f"\nSummary: {self.num_sessions} tested, {len(sessions)} unique, {clean_count} clean")
        
        return ScanSummary(
            total_sessions=self.num_sessions,
            unique_ips=len(sessions),
            duplicates=duplicates,
            failures=failures,
            clean_ips=clean_count,
            results=results,
        )
