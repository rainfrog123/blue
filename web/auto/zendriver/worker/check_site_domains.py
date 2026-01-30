#%% Imports and Setup - load required libraries for async DNS queries and domain generation
"""
Enumerate all 4-character .site domains and check availability
"""
import itertools
import string
import asyncio
import aiodns
from typing import AsyncGenerator

#%% Domain Generator - define charset (a-z, 0-9) and generate all 36^4 = 1,679,616 possible 4-char .site domains
chars = string.ascii_lowercase + string.digits  # a-z, 0-9

def generate_4char_domains() -> list[str]:
    """Generate all possible 4-character domain names"""
    combinations = itertools.product(chars, repeat=4)
    return [''.join(combo) + '.site' for combo in combinations]

# Total combinations: 36^4 = 1,679,616
print(f"Character set: {chars}")
print(f"Total 4-char combinations: {len(chars)**4:,}")

#%% Single Domain Checker - query DNS NS records (NXDOMAIN = available, has NS = taken)
async def check_domain_available(resolver: aiodns.DNSResolver, domain: str) -> tuple[str, bool]:
    """
    Check if domain is available by attempting DNS resolution.
    Returns (domain, is_available)
    
    Note: No DNS records doesn't guarantee availability, but registered 
    domains typically have some DNS records.
    """
    try:
        await resolver.query(domain, 'NS')
        return (domain, False)  # Has NS records, likely registered
    except aiodns.error.DNSError as e:
        if e.args[0] == aiodns.error.ARES_ENOTFOUND:
            return (domain, True)  # NXDOMAIN - likely available
        return (domain, None)  # Other error, unknown status

#%% Batch Checker - process multiple domains in parallel with semaphore concurrency control
async def check_domains_batch(domains: list[str], concurrency: int = 100) -> AsyncGenerator[tuple[str, bool], None]:
    """Check multiple domains with controlled concurrency"""
    resolver = aiodns.DNSResolver()
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check_with_semaphore(domain: str):
        async with semaphore:
            return await check_domain_available(resolver, domain)
    
    tasks = [check_with_semaphore(d) for d in domains]
    for coro in asyncio.as_completed(tasks):
        yield await coro

#%% Main Scanner - iterate all domains in batches, save results to file, supports resume
async def find_available_domains(
    start_from: str = None,
    max_results: int = 1000,
    concurrency: int = 50,
    save_progress: bool = True
):
    """
    Find available 4-character .site domains
    
    Args:
        start_from: Resume from this domain (e.g., 'abcd.site')
        max_results: Stop after finding this many available domains
        concurrency: Number of concurrent DNS queries
        save_progress: Save results to file as we go
    """
    all_domains = generate_4char_domains()
    
    # Resume from a specific point if specified
    if start_from:
        try:
            start_idx = all_domains.index(start_from)
            all_domains = all_domains[start_idx:]
            print(f"Resuming from {start_from} (index {start_idx})")
        except ValueError:
            print(f"Domain {start_from} not found, starting from beginning")
    
    available = []
    checked = 0
    
    output_file = "available_4char_site_domains.txt"
    
    print(f"Checking {len(all_domains):,} domains with concurrency={concurrency}...")
    print(f"Will stop after finding {max_results} available domains")
    print("-" * 50)
    
    # Process in batches
    batch_size = 1000
    for i in range(0, len(all_domains), batch_size):
        batch = all_domains[i:i+batch_size]
        
        async for domain, is_available in check_domains_batch(batch, concurrency):
            checked += 1
            
            if is_available:
                available.append(domain)
                print(f"[{checked:,}] AVAILABLE: {domain}")
                
                if save_progress:
                    with open(output_file, 'a') as f:
                        f.write(domain + '\n')
                
                if len(available) >= max_results:
                    print(f"\nReached {max_results} available domains, stopping.")
                    return available
            
            if checked % 1000 == 0:
                print(f"Progress: {checked:,} checked, {len(available)} available found")
    
    print(f"\nDone! Checked {checked:,} domains, found {len(available)} available")
    return available

#%% Quick Test - verify checker works with 8 sample domains before full scan
sample_domains = [
    'aaaa.site', 'zzzz.site', '0000.site', '9999.site',
    'test.site', 'free.site', 'cool.site', 'best.site'
]

async def quick_test():
    resolver = aiodns.DNSResolver()
    print("Quick test - checking sample domains:")
    print("-" * 40)
    for domain in sample_domains:
        result = await check_domain_available(resolver, domain)
        status = "AVAILABLE" if result[1] else "TAKEN" if result[1] is False else "UNKNOWN"
        print(f"{domain}: {status}")

# In Jupyter/IPython, use await directly:
await quick_test()

#%% Full Scan Launcher - uncomment to check all ~1.6M domains, stops after 100 available
# await find_available_domains(max_results=100, concurrency=50)

#%% WHOIS Checker (Alternative) - more accurate than DNS but much slower
async def check_whois_available(domain: str) -> tuple[str, bool]:
    """Check domain availability via WHOIS (more accurate but slower)"""
    import whois
    try:
        w = whois.whois(domain)
        # If domain_name is None or empty, domain is likely available
        if w.domain_name is None:
            return (domain, True)
        return (domain, False)
    except whois.parser.PywhoisError:
        return (domain, True)  # WHOIS error usually means not registered
    except Exception as e:
        return (domain, None)  # Unknown

#%% Letter-Only Generator - only a-z (no numbers) = 26^4 = 456,976 combinations
def generate_letter_only_domains() -> list[str]:
    """Generate 4-char domains using only letters (smaller set)"""
    chars = string.ascii_lowercase
    combinations = itertools.product(chars, repeat=4)
    return [''.join(combo) + '.site' for combo in combinations]

print(f"\nLetter-only combinations: {26**4:,}")

#%% Namecheap WebSocket Checker - uses Namecheap's domain lookup API via WebSocket
import json
import time
import websockets
from dataclasses import dataclass
from typing import Optional

@dataclass
class DomainResult:
    """Result from Namecheap domain check"""
    name: str
    available: bool
    premium: bool = False
    fee: Optional[float] = None
    renewal_fee: Optional[float] = None
    registrar: Optional[str] = None
    created_year: Optional[int] = None
    error: Optional[str] = None

class NamecheapChecker:
    """Check domain availability via Namecheap's WebSocket API"""
    
    WS_URL = "wss://domains-ws.revved.com/v1/ws?batch=false&whois=true&trace=true"
    
    def __init__(self):
        self.ws = None
        self._req_counter = 0
    
    def _generate_req_id(self) -> str:
        """Generate unique request ID"""
        self._req_counter += 1
        return f"{int(time.time() * 1000)}{self._req_counter:04d}"
    
    async def connect(self):
        """Establish WebSocket connection"""
        self.ws = await websockets.connect(
            self.WS_URL,
            origin="https://www.namecheap.com",
            extra_headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en-GB;q=0.9,en;q=0.8",
            }
        )
    
    async def close(self):
        """Close WebSocket connection"""
        if self.ws:
            await self.ws.close()
            self.ws = None
    
    async def check_domains(self, domains: list[str]) -> dict[str, DomainResult]:
        """
        Check availability of multiple domains.
        
        Args:
            domains: List of domain names (e.g., ['test.site', 'cool.io'])
            
        Returns:
            Dict mapping domain name to DomainResult
        """
        if not self.ws:
            await self.connect()
        
        req_id = self._generate_req_id()
        
        # Send request
        request = {
            "type": "domainStatus",
            "reqID": req_id,
            "data": {
                "domains": [d.lower() for d in domains]
            }
        }
        await self.ws.send(json.dumps(request))
        
        # Collect responses
        results = {}
        expected_count = len(domains)
        
        while len(results) < expected_count:
            try:
                msg = await asyncio.wait_for(self.ws.recv(), timeout=30.0)
                data = json.loads(msg)
                
                if data.get("type") == "domainStatusResponse" and data.get("reqID") == req_id:
                    domain_data = data.get("data", {})
                    name = domain_data.get("name")
                    
                    if name:
                        result = DomainResult(
                            name=name,
                            available=domain_data.get("available", False),
                            premium=domain_data.get("premium", False),
                            error=domain_data.get("error"),
                        )
                        
                        # Extract fee info
                        fee_info = domain_data.get("fee", {})
                        if fee_info:
                            result.fee = fee_info.get("amount")
                        
                        renewal_info = domain_data.get("renewalFee", {})
                        if renewal_info:
                            result.renewal_fee = renewal_info.get("amount")
                        
                        # Extract extra info
                        extra = domain_data.get("extra", {})
                        if extra:
                            result.registrar = extra.get("registrar")
                            result.created_year = extra.get("createdYear")
                        
                        # Also check whois for created year
                        whois = domain_data.get("whois", {})
                        if whois and not result.created_year:
                            result.created_year = whois.get("createdYear")
                        
                        results[name] = result
                        
            except asyncio.TimeoutError:
                print(f"Timeout waiting for responses, got {len(results)}/{expected_count}")
                break
        
        return results
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, *args):
        await self.close()


async def check_namecheap(domains: list[str]) -> dict[str, DomainResult]:
    """
    Convenience function to check domains via Namecheap.
    
    Example:
        results = await check_namecheap(['test.site', 'cool.io', 'eris.dev'])
        for name, r in results.items():
            print(f"{name}: {'AVAILABLE' if r.available else 'TAKEN'}")
    """
    async with NamecheapChecker() as checker:
        return await checker.check_domains(domains)


async def find_available_namecheap(
    domains: list[str],
    batch_size: int = 30,
    delay: float = 0.5,
) -> list[DomainResult]:
    """
    Find available domains using Namecheap API.
    
    Args:
        domains: List of domains to check
        batch_size: How many domains per WebSocket request (max ~30 recommended)
        delay: Seconds to wait between batches
        
    Returns:
        List of DomainResult for available domains
    """
    available = []
    checked = 0
    
    async with NamecheapChecker() as checker:
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i+batch_size]
            
            try:
                results = await checker.check_domains(batch)
                
                for name, result in results.items():
                    checked += 1
                    if result.available:
                        available.append(result)
                        status = "PREMIUM" if result.premium else "AVAILABLE"
                        fee_str = f" (${result.fee})" if result.fee else ""
                        print(f"[{checked}] {status}: {name}{fee_str}")
                    elif result.error:
                        print(f"[{checked}] ERROR: {name} - {result.error}")
                
                if i + batch_size < len(domains):
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                print(f"Error checking batch: {e}")
                # Reconnect on error
                await checker.close()
                await checker.connect()
    
    print(f"\nDone! Checked {checked} domains, found {len(available)} available")
    return available


#%% Namecheap Test - verify WebSocket checker works
async def test_namecheap():
    """Test Namecheap WebSocket API with sample domains"""
    test_domains = [
        'eris.site', 'er1is.site', 'test.site', 'aaaa.site',
        'zzzz.site', 'cool.io', 'test.dev'
    ]
    
    print("Testing Namecheap WebSocket API...")
    print("-" * 50)
    
    results = await check_namecheap(test_domains)
    
    for name, r in sorted(results.items()):
        if r.error:
            status = f"ERROR: {r.error}"
        elif r.available:
            status = "AVAILABLE"
            if r.premium:
                status += f" (PREMIUM ${r.fee})"
        else:
            status = f"TAKEN"
            if r.registrar:
                status += f" by {r.registrar}"
            if r.created_year:
                status += f" since {r.created_year}"
        
        print(f"{name}: {status}")

# Uncomment to test:
# await test_namecheap()
