#!/usr/bin/env python3
"""
Domain Availability Checker
Checks domain availability for specified TLDs using WHOIS and DNS lookups.
"""

import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import whois
    HAS_PYTHON_WHOIS = True
except ImportError:
    HAS_PYTHON_WHOIS = False

# TLDs to check
TLDS = [".store", ".online"]

# Rate limiting delay (seconds between checks)
DELAY_BETWEEN_CHECKS = 0.5


def load_words(filepath: str = "words.json") -> list[str]:
    """Load words from JSON file."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: {filepath} not found")
        sys.exit(1)
    
    with open(path) as f:
        data = json.load(f)
    
    return data.get("words", [])


def check_dns(domain: str) -> bool:
    """Check if domain resolves via DNS. Returns True if NOT registered (available)."""
    try:
        socket.gethostbyname(domain)
        return False  # Domain resolves, likely taken
    except socket.gaierror:
        return True  # No DNS record, might be available


def check_whois_python(domain: str) -> bool | None:
    """Check domain using python-whois library."""
    if not HAS_PYTHON_WHOIS:
        return None
    
    try:
        w = whois.whois(domain)
        # If domain_name is None or empty, domain is likely available
        if w.domain_name is None:
            return True
        return False
    except whois.parser.PywhoisError:
        return True  # Domain not found = available
    except Exception:
        return None


def check_whois_cmd(domain: str) -> bool | None:
    """
    Check domain via WHOIS command. Returns:
    - True if available
    - False if taken
    - None if check failed
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout.lower()
        
        # Common indicators of available domain
        available_indicators = [
            "no match",
            "not found",
            "no data found",
            "no entries found",
            "domain not found",
            "no object found",
            "available",
            "status: free",
        ]
        
        # Common indicators of taken domain
        taken_indicators = [
            "domain name:",
            "registrant:",
            "creation date:",
            "registered on:",
            "registry domain id:",
        ]
        
        for indicator in available_indicators:
            if indicator in output:
                return True
        
        for indicator in taken_indicators:
            if indicator in output:
                return False
        
        return None  # Uncertain
        
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def check_whois(domain: str) -> bool | None:
    """Check domain via WHOIS (tries python library first, then command)."""
    # Try python-whois library first
    result = check_whois_python(domain)
    if result is not None:
        return result
    
    # Fallback to whois command
    return check_whois_cmd(domain)


def check_domain(domain: str) -> dict:
    """Check single domain availability."""
    result = {
        "domain": domain,
        "available": None,
        "method": None,
    }
    
    # Try WHOIS first
    whois_result = check_whois(domain)
    if whois_result is not None:
        result["available"] = whois_result
        result["method"] = "whois"
        return result
    
    # Fallback to DNS check
    dns_result = check_dns(domain)
    result["available"] = dns_result
    result["method"] = "dns"
    
    return result


def check_domains(words: list[str], tlds: list[str], delay: float = DELAY_BETWEEN_CHECKS) -> list[dict]:
    """Check all word+TLD combinations."""
    domains = [f"{word}{tld}" for word in words for tld in tlds]
    results = []
    
    print(f"Checking {len(domains)} domains ({len(words)} words × {len(tlds)} TLDs)...")
    print("-" * 60)
    
    for i, domain in enumerate(domains, 1):
        result = check_domain(domain)
        results.append(result)
        
        status = "✓ AVAILABLE" if result["available"] else "✗ TAKEN" if result["available"] is False else "? UNKNOWN"
        print(f"[{i}/{len(domains)}] {domain:30} {status}")
        
        time.sleep(delay)
    
    return results


def print_summary(results: list[dict]):
    """Print summary of available domains."""
    available = [r for r in results if r["available"] is True]
    taken = [r for r in results if r["available"] is False]
    unknown = [r for r in results if r["available"] is None]
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total checked: {len(results)}")
    print(f"Available:     {len(available)}")
    print(f"Taken:         {len(taken)}")
    print(f"Unknown:       {len(unknown)}")
    
    if available:
        print("\n" + "-" * 60)
        print("AVAILABLE DOMAINS:")
        print("-" * 60)
        for r in available:
            print(f"  ✓ {r['domain']}")
    
    # Save results to file
    output_file = "domain_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "summary": {
                "total": len(results),
                "available": len(available),
                "taken": len(taken),
                "unknown": len(unknown),
            },
            "available_domains": [r["domain"] for r in available],
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to {output_file}")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check domain availability")
    parser.add_argument(
        "-w", "--words",
        default="words.json",
        help="Path to words JSON file (default: words.json)"
    )
    parser.add_argument(
        "-t", "--tlds",
        nargs="+",
        default=TLDS,
        help=f"TLDs to check (default: {' '.join(TLDS)})"
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=DELAY_BETWEEN_CHECKS,
        help=f"Delay between checks in seconds (default: {DELAY_BETWEEN_CHECKS})"
    )
    
    args = parser.parse_args()
    
    # Ensure TLDs have dots
    tlds = [t if t.startswith(".") else f".{t}" for t in args.tlds]
    
    words = load_words(args.words)
    print(f"Loaded {len(words)} words from {args.words}")
    print(f"TLDs: {', '.join(tlds)}")
    print()
    
    results = check_domains(words, tlds, delay=args.delay)
    print_summary(results)


if __name__ == "__main__":
    main()
