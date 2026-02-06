#!/usr/bin/env python3
"""
IP Reputation Checker using IPQS
Check the fraud score and other details for any IP address
"""

import sys
import argparse
import requests

# Add lib to path for imports
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parents[2]))
from lib.config import get_ipqs_credentials, API_ENDPOINTS, DEFAULT_USER_AGENT, get_score_emoji


def validate_ip(ip: str) -> bool:
    """Validate IP address format (IPv4 and IPv6)"""
    import re
    
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    # IPv6 (basic check)
    if ':' in ip and all(c in '0123456789abcdefABCDEF:' for c in ip):
        return True
    
    return False


def format_bool(value: bool) -> str:
    """Format boolean with emoji"""
    if value is True:
        return "Yes"
    elif value is False:
        return "No"
    return f"? {value}"


def check_ip(ip_address: str) -> dict:
    """Check IP reputation using IPQS API"""
    creds = get_ipqs_credentials()
    
    url = f"{API_ENDPOINTS['ipqs']}/{creds['api_key']}/{ip_address}"
    params = {
        'strictness': 3,
        'user_agent': DEFAULT_USER_AGENT,
        'user_language': 'en-US',
        'fast': 'false',
        'mobile': 'false'
    }
    
    response = requests.get(url, params=params, timeout=30)
    return response.json()


def print_report(ip_address: str, data: dict):
    """Print formatted IP report"""
    print()
    print("=" * 50)
    print(f"IPQS IP Analysis for: {ip_address}")
    print("=" * 50)
    
    # Fraud Analysis
    fraud_score = data.get('fraud_score', 'N/A')
    print()
    print("FRAUD ANALYSIS")
    print("-" * 20)
    print(f"Fraud Score:       {get_score_emoji(fraud_score)} {fraud_score}/100")
    print(f"Recent Abuse:      {format_bool(data.get('recent_abuse', False))}")
    print(f"Abuse Velocity:    {data.get('abuse_velocity', 'N/A')}")
    
    # Location
    print()
    print("LOCATION INFORMATION")
    print("-" * 20)
    print(f"Country:          {data.get('country_code', 'N/A')}")
    print(f"Region/State:     {data.get('region', 'N/A')}")
    print(f"City:             {data.get('city', 'N/A')}")
    print(f"ZIP Code:         {data.get('zip_code', 'N/A')}")
    print(f"Latitude:         {data.get('latitude', 'N/A')}")
    print(f"Longitude:        {data.get('longitude', 'N/A')}")
    print(f"Timezone:         {data.get('timezone', 'N/A')}")
    
    # Network
    print()
    print("NETWORK INFORMATION")
    print("-" * 20)
    print(f"ISP:              {data.get('ISP', 'N/A')}")
    print(f"ASN:              {data.get('ASN', 'N/A')}")
    print(f"Organization:     {data.get('organization', 'N/A')}")
    print(f"Connection Type:  {data.get('connection_type', 'N/A')}")
    
    # Proxy/VPN Detection
    print()
    print("PROXY/VPN DETECTION")
    print("-" * 20)
    print(f"Proxy:            {format_bool(data.get('proxy', False))}")
    print(f"VPN:              {format_bool(data.get('vpn', False))}")
    print(f"Active VPN:       {format_bool(data.get('active_vpn', False))}")
    print(f"TOR:              {format_bool(data.get('tor', False))}")
    print(f"Active TOR:       {format_bool(data.get('active_tor', False))}")
    
    # Bot/Crawler
    print()
    print("BOT/CRAWLER DETECTION")
    print("-" * 20)
    print(f"Bot Status:       {format_bool(data.get('bot_status', False))}")
    print(f"Is Crawler:       {format_bool(data.get('is_crawler', False))}")
    print(f"Mobile:           {format_bool(data.get('mobile', False))}")
    
    # Risk Assessment
    print()
    print("RISK ASSESSMENT")
    print("-" * 20)
    if isinstance(fraud_score, int):
        if fraud_score == 0:
            level = "VERY LOW (Excellent)"
        elif fraud_score < 20:
            level = "LOW (Good)"
        elif fraud_score < 40:
            level = "MODERATE (Acceptable)"
        elif fraud_score < 70:
            level = "HIGH (Caution)"
        else:
            level = "VERY HIGH (Dangerous)"
        print(f"Risk Level:       {level}")
    else:
        print("Risk Level:       Unknown")
    
    print()
    print("=" * 50)
    print(f"Analysis completed for: {ip_address}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description='Check IP reputation using IPQS')
    parser.add_argument('ip', nargs='?', default='94.177.14.241',
                        help='IP address to check (IPv4 or IPv6)')
    args = parser.parse_args()
    
    ip_address = args.ip
    
    if not validate_ip(ip_address):
        print(f"Invalid IP address format: {ip_address}")
        print("Supported formats: IPv4 (e.g., 192.168.1.1) and IPv6 (e.g., 2001:db8::1)")
        sys.exit(1)
    
    print(f"Checking IP: {ip_address}")
    
    try:
        data = check_ip(ip_address)
        
        if not data.get('success'):
            print(f"API Error: {data.get('message', 'Unknown error')}")
            sys.exit(1)
        
        print_report(ip_address, data)
        
    except requests.RequestException as e:
        print(f"Failed to connect to IPQS API: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
