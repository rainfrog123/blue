"""Batch-scan Decodo sticky sessions and score exits with IPQS."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from .client import DecodoClient, ExitInfo
from .ipqs import IPQSChecker, IPQSResult


@dataclass
class ScanResult:
    session: ExitInfo
    ipqs: Optional[IPQSResult] = None
    error: Optional[str] = None
    clean_threshold: int = 50

    @property
    def is_clean(self) -> bool:
        if self.ipqs is None:
            return False
        return self.ipqs.fraud_score < self.clean_threshold


@dataclass
class ScanSummary:
    total_sessions: int
    unique_ips: int
    duplicates: int
    failures: int
    clean_ips: int
    results: list[ScanResult] = field(default_factory=list)

    @property
    def best_result(self) -> Optional[ScanResult]:
        clean = [r for r in self.results if r.is_clean and r.ipqs]
        if not clean:
            return None
        return min(clean, key=lambda r: r.ipqs.fraud_score)  # type: ignore[union-attr]


class SessionScanner:
    """
    Open N sticky sessions, collect unique exit IPs, score with IPQS.

    Session labels are random fruit+suffix strings (opaque sticky ids).
    """

    def __init__(
        self,
        country: str = "gb",
        num_sessions: int = 10,
        session_duration: int = 60,
        clean_threshold: int = 50,
        max_workers: int = 10,
        timeout: int = 45,
        protocol: Optional[str] = None,
    ):
        self.country = country
        self.num_sessions = num_sessions
        self.session_duration = session_duration
        self.clean_threshold = clean_threshold
        self.max_workers = max_workers
        self.timeout = timeout
        self.protocol = protocol

        self.client = DecodoClient(
            country=country,
            session_duration=session_duration,
            timeout=timeout,
            protocol=protocol,
        )
        self.ipqs = IPQSChecker(timeout=15, clean_threshold=clean_threshold)

    def _probe(self, index: int) -> tuple[Optional[ExitInfo], Optional[str]]:
        name = self.client.generate_session_name()
        try:
            return self.client.get_current_ip(session=name), None
        except Exception as exc:  # noqa: BLE001 — surface per-session failures
            return None, f"{name}: {exc}"

    def _score(self, ip: str) -> tuple[Optional[IPQSResult], Optional[str]]:
        try:
            return self.ipqs.check(ip), None
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    def scan(self, verbose: bool = True) -> ScanSummary:
        if verbose:
            proto = self.protocol or self.client.protocol
            print("=" * 50)
            print("Decodo IPs check")
            print("=" * 50)
            print(f"Country:   {self.country.upper()}")
            print(f"Protocol:  {proto}")
            print(f"Sessions:  {self.num_sessions}")
            print(f"Duration:  {self.session_duration} min")
            print("=" * 50)
            print(f"\n[Phase 1] Probing {self.num_sessions} sticky sessions...")

        sessions: list[ExitInfo] = []
        seen: set[str] = set()
        duplicates = 0
        failures = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._probe, i): i for i in range(1, self.num_sessions + 1)
            }
            for future in as_completed(futures):
                idx = futures[future]
                info, err = future.result()
                if err or info is None:
                    failures += 1
                    if verbose:
                        print(f"  FAIL #{idx}: {(err or 'unknown')[:60]}")
                    continue
                if info.ip in seen:
                    duplicates += 1
                    if verbose:
                        print(
                            f"  DUP  #{idx} {info.session_name}: {info.ip}"
                        )
                else:
                    seen.add(info.ip)
                    sessions.append(info)
                    if verbose:
                        print(
                            f"  OK   #{idx} {info.session_name}: {info.ip} ({info.city})"
                        )

        if verbose:
            print(
                f"\nUnique: {len(sessions)} | Duplicates: {duplicates} | Failures: {failures}"
            )

        if not sessions:
            return ScanSummary(
                total_sessions=self.num_sessions,
                unique_ips=0,
                duplicates=duplicates,
                failures=failures,
                clean_ips=0,
            )

        if verbose:
            print(f"\n[Phase 2] IPQS scoring {len(sessions)} IPs...")

        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._score, s.ip): s for s in sessions}
            for future in as_completed(futures):
                info = futures[future]
                ipqs, err = future.result()
                row = ScanResult(
                    session=info,
                    ipqs=ipqs,
                    error=err,
                    clean_threshold=self.clean_threshold,
                )
                results.append(row)
                if verbose:
                    if err:
                        print(f"  FAIL {info.ip}: {err[:50]}")
                    elif ipqs:
                        print(
                            f"  [{ipqs.risk_level}] {info.ip}: "
                            f"score {ipqs.fraud_score} ({info.city})"
                        )

        results.sort(key=lambda r: r.ipqs.fraud_score if r.ipqs else 999)
        clean_count = sum(1 for r in results if r.is_clean)

        if verbose:
            print(f"\n{'=' * 50}")
            print(f"Clean IPs (score < {self.clean_threshold})")
            print("=" * 50)
            for row in results:
                if row.is_clean and row.ipqs:
                    print(f"\n[{row.ipqs.risk_level}] score {row.ipqs.fraud_score}")
                    print(f"   IP:      {row.session.ip}")
                    print(f"   City:    {row.session.city}")
                    print(f"   Session: {row.session.session_name}")
                    print(f"   URL:     {row.session.proxy_url}")

            best = ScanSummary(
                total_sessions=self.num_sessions,
                unique_ips=len(sessions),
                duplicates=duplicates,
                failures=failures,
                clean_ips=clean_count,
                results=results,
            ).best_result
            if best and best.ipqs:
                print(f"\n{'=' * 50}")
                print(f"Best (score {best.ipqs.fraud_score})")
                print("=" * 50)
                print(best.session.proxy_url)

            print(
                f"\nSummary: {self.num_sessions} tested, "
                f"{len(sessions)} unique, {clean_count} clean"
            )

        return ScanSummary(
            total_sessions=self.num_sessions,
            unique_ips=len(sessions),
            duplicates=duplicates,
            failures=failures,
            clean_ips=clean_count,
            results=results,
        )
