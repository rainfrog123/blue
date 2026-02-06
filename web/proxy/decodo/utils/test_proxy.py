#!/usr/bin/env python3
"""
Simple Proxy Connection Tester
Tests a single proxy connection and displays the response
"""

import sys
import argparse

# Add lib to path for imports
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[1]))
from lib.config import (
    get_decodo_credentials,
    build_socks5_proxy_url,
    build_https_proxy_url,
    API_ENDPOINTS
)

import requests


def test_socks5_proxy(country: str = 'gb', session: str = None, session_duration: int = 60):
    """Test SOCKS5 proxy connection"""
    proxy_url = build_socks5_proxy_url(country=country, session=session, session_duration=session_duration)
    
    print(f"Testing SOCKS5 proxy...")
    print(f"Proxy URL: {proxy_url}")
    print()
    
    result = requests.get(
        API_ENDPOINTS['decodo_ip'],
        proxies={'http': proxy_url, 'https': proxy_url},
        timeout=30
    )
    
    return result.json()


def test_https_proxy(country: str = 'gb', session_duration: int = 60):
    """Test HTTPS proxy connection"""
    proxy_url = build_https_proxy_url(country=country, session_duration=session_duration)
    
    print(f"Testing HTTPS proxy...")
    print(f"Proxy URL: {proxy_url}")
    print()
    
    result = requests.get(
        API_ENDPOINTS['decodo_ip'],
        proxies={'http': proxy_url, 'https': proxy_url},
        timeout=30
    )
    
    return result.json()


def main():
    parser = argparse.ArgumentParser(description='Test Decodo proxy connection')
    parser.add_argument('--type', choices=['socks5', 'https'], default='socks5',
                        help='Proxy type to test (default: socks5)')
    parser.add_argument('--country', '-c', default='gb',
                        help='Country code (default: gb)')
    parser.add_argument('--session', '-s', default=None,
                        help='Session name (for sticky sessions)')
    parser.add_argument('--duration', '-d', type=int, default=60,
                        help='Session duration in minutes (default: 60)')
    args = parser.parse_args()
    
    try:
        if args.type == 'socks5':
            result = test_socks5_proxy(
                country=args.country,
                session=args.session,
                session_duration=args.duration
            )
        else:
            result = test_https_proxy(
                country=args.country,
                session_duration=args.duration
            )
        
        print("Response:")
        print("-" * 40)
        
        if 'proxy' in result:
            print(f"IP: {result['proxy'].get('ip', 'N/A')}")
        if 'city' in result:
            print(f"City: {result['city'].get('name', 'N/A')}")
        if 'country' in result:
            print(f"Country: {result['country'].get('name', 'N/A')} ({result['country'].get('code', 'N/A')})")
        
        print()
        print("Full response:", result)
        
    except requests.RequestException as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
