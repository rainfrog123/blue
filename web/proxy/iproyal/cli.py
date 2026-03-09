#!/usr/bin/env python3
"""
IPRoyal Proxy CLI

Commands:
    scan     - Scan multiple sessions to find clean IPs
    check    - Check a single IP's fraud score
    test     - Test proxy connection
"""

import argparse
import sys


def cmd_scan(args):
    """Scan multiple proxy sessions."""
    from iproyal import SessionScanner
    
    scanner = SessionScanner(
        country=args.country,
        num_sessions=args.sessions,
        lifetime=args.lifetime,
        max_workers=args.workers,
    )
    
    summary = scanner.scan(verbose=True)
    
    # Exit with error if no clean IPs found
    sys.exit(0 if summary.clean_ips > 0 else 1)


def cmd_check(args):
    """Check IP reputation."""
    from iproyal import IPQSChecker
    
    checker = IPQSChecker()
    
    for ip in args.ips:
        try:
            result = checker.check(ip)
            print(f"\n{'=' * 50}")
            print(f"IP: {ip}")
            print(f"{'=' * 50}")
            print(f"Fraud Score: {result.emoji} {result.fraud_score}/100")
            print(f"Risk Level:  {result.risk_level}")
            print(f"Location:    {result.city}, {result.country_code}")
            print(f"ISP:         {result.isp}")
            print(f"Proxy:       {'Yes' if result.is_proxy else 'No'}")
            print(f"VPN:         {'Yes' if result.is_vpn else 'No'}")
            print(f"TOR:         {'Yes' if result.is_tor else 'No'}")
            print(f"Bot:         {'Yes' if result.is_bot else 'No'}")
            print(f"Recent Abuse: {'Yes' if result.recent_abuse else 'No'}")
        except Exception as e:
            print(f"Error checking {ip}: {e}")


def cmd_test(args):
    """Test proxy connection."""
    from iproyal import IPRoyalClient
    
    client = IPRoyalClient(
        country=args.country,
        lifetime=args.lifetime,
    )
    
    print(f"Testing proxy connection to {args.country.upper()}...")
    
    try:
        if args.session:
            with client.session(args.session) as session:
                info = session.get_ip()
        else:
            info = client.get_current_ip()
        
        print(f"\n{'=' * 50}")
        print(f"Connection Successful")
        print(f"{'=' * 50}")
        print(f"IP:       {info.ip}")
        print(f"Country:  {info.country.upper()}")
        print(f"Session:  {info.session_id}")
        print(f"Lifetime: {info.lifetime}")
        print(f"\nProxy URL:")
        print(info.proxy_url)
        
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="IPRoyal Proxy CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan sessions for clean IPs")
    scan_parser.add_argument("-c", "--country", default="de", help="Country code (default: de)")
    scan_parser.add_argument("-n", "--sessions", type=int, default=10, help="Number of sessions (default: 10)")
    scan_parser.add_argument("-l", "--lifetime", default="1h", help="Session lifetime (default: 1h)")
    scan_parser.add_argument("-w", "--workers", type=int, default=10, help="Max concurrent workers (default: 10)")
    scan_parser.set_defaults(func=cmd_scan)
    
    # check command
    check_parser = subparsers.add_parser("check", help="Check IP fraud score")
    check_parser.add_argument("ips", nargs="+", help="IP address(es) to check")
    check_parser.set_defaults(func=cmd_check)
    
    # test command
    test_parser = subparsers.add_parser("test", help="Test proxy connection")
    test_parser.add_argument("-c", "--country", default="de", help="Country code (default: de)")
    test_parser.add_argument("-l", "--lifetime", default="1h", help="Session lifetime (default: 1h)")
    test_parser.add_argument("-s", "--session", help="Session ID for sticky IP")
    test_parser.set_defaults(func=cmd_test)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == "__main__":
    main()
