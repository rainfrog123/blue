#!/usr/bin/env python3
import requests
import concurrent.futures
from urllib.parse import urlparse

def test_proxy(proxy_line):
    try:
        proxy = proxy_line.strip()
        if not proxy:
            return None, None
        
        # Parse proxy format: user:pass@host:port
        if '@' not in proxy:
            return f"{proxy}: Invalid format", None
        
        auth_part, host_part = proxy.split('@')
        username, password = auth_part.split(':')
        host, port = host_part.split(':')
        
        proxy_dict = {
            'http': f'http://{username}:{password}@{host}:{port}',
            'https': f'http://{username}:{password}@{host}:{port}'
        }
        
        response = requests.get('http://httpbin.org/ip', 
                              proxies=proxy_dict, 
                              timeout=5)
        
        if response.status_code == 200:
            ip = response.json().get('origin')
            return f"{proxy}: {ip}", proxy
        else:
            return f"{proxy}: HTTP {response.status_code}", None
            
    except Exception as e:
        return f"{proxy}: Error - {str(e)}", None

def main():
    with open('proxies.txt', 'r') as f:
        proxies = f.readlines()[:20]  # Test first 20
    
    print(f"Testing {len(proxies)} proxies...\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(test_proxy, proxies))
    
    working_proxies = []
    for result, proxy in results:
        if result:
            print(result)
            if proxy:  # If proxy is not None, it's working
                working_proxies.append(proxy)
    
    print(f"\n--- SUMMARY ---")
    print(f"Working proxies: {len(working_proxies)}/{len(proxies)}")
    if working_proxies:
        print("\nWorkable proxies:")
        for proxy in working_proxies:
            print(proxy)

if __name__ == "__main__":
    main()
