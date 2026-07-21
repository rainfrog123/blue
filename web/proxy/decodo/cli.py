#!/usr/bin/env python3
"""Decodo CLI — test / url / ips-check / ip-check."""

from __future__ import annotations

import argparse
import sys


def cmd_test(args: argparse.Namespace) -> None:
    from decodo import DecodoClient

    client = DecodoClient(
        country=args.country,
        session_duration=args.duration,
        protocol=args.protocol,
    )
    print(f"Testing {client.protocol} -> {args.country.upper()}...")

    try:
        if args.session:
            with client.session(args.session) as sticky:
                info = sticky.get_ip()
        else:
            info = client.get_current_ip()
    except Exception as exc:  # noqa: BLE001
        print(f"Connection failed: {exc}")
        sys.exit(1)

    print()
    print("=" * 50)
    print("OK")
    print("=" * 50)
    print(f"IP:      {info.ip}")
    print(f"City:    {info.city}")
    print(f"ISP:     {info.isp}")
    print(f"Country: {info.country_name} ({info.country_code})")
    print(f"Session: {info.session_name or '(none)'}")
    print(f"Port:    {info.port}")
    print()
    print(info.proxy_url)


def cmd_url(args: argparse.Namespace) -> None:
    from decodo import build_proxy_url

    url = build_proxy_url(
        country=args.country,
        session_duration=args.duration,
        session=args.session,
        protocol=args.protocol,
        port=args.port,
    )
    print(url)


def cmd_ips_check(args: argparse.Namespace) -> None:
    """Probe many sticky sessions and score exit IPs with IPQS."""
    from decodo import SessionScanner

    scanner = SessionScanner(
        country=args.country,
        num_sessions=args.sessions,
        session_duration=args.duration,
        max_workers=args.workers,
        protocol=args.protocol,
        clean_threshold=args.threshold,
    )
    summary = scanner.scan(verbose=True)
    sys.exit(0 if summary.clean_ips > 0 else 1)


def cmd_ip_check(args: argparse.Namespace) -> None:
    """IPQS lookup for one or more known IPs."""
    from decodo import IPQSChecker

    checker = IPQSChecker()
    for ip in args.ips:
        try:
            result = checker.check(ip)
        except Exception as exc:  # noqa: BLE001
            print(f"Error checking {ip}: {exc}")
            continue
        print()
        print("=" * 50)
        print(f"IP: {ip}")
        print("=" * 50)
        print(f"Fraud Score:  {result.fraud_score}/100")
        print(f"Risk Level:   {result.risk_level}")
        print(f"Location:     {result.city}, {result.country_code}")
        print(f"ISP:          {result.isp}")
        print(f"Proxy / VPN:  {result.is_proxy} / {result.is_vpn}")
        print(f"TOR / Bot:    {result.is_tor} / {result.is_bot}")
        print(f"Recent abuse: {result.recent_abuse}")


def _add_proxy_flags(p: argparse.ArgumentParser, *, need_session: bool = False) -> None:
    p.add_argument("-c", "--country", default="gb", help="Country code (default: gb)")
    p.add_argument(
        "-d",
        "--duration",
        type=int,
        default=60,
        help="Sticky session duration minutes (default: 60)",
    )
    p.add_argument(
        "-p",
        "--protocol",
        default="socks5h",
        choices=["http", "https", "socks5", "socks5h"],
        help="Proxy protocol (default: socks5h)",
    )
    if need_session:
        p.add_argument(
            "-s",
            "--session",
            help="Sticky session id (opaque: apple, uuid hex, ...)",
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decodo proxy toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py test -c gb -s apple
  python cli.py url  -c gb -s banana -p socks5h
  python cli.py ips-check -c gb -n 10 -p socks5h
  python cli.py ip-check 8.8.8.8
""",
    )
    sub = parser.add_subparsers(dest="command")

    test_p = sub.add_parser("test", help="Probe exit IP via Decodo")
    _add_proxy_flags(test_p, need_session=True)
    test_p.set_defaults(func=cmd_test)

    url_p = sub.add_parser("url", help="Print a proxy URL (no network)")
    _add_proxy_flags(url_p, need_session=True)
    url_p.add_argument("--port", type=int, help="Override port")
    url_p.set_defaults(func=cmd_url)

    ips_p = sub.add_parser(
        "ips-check",
        aliases=["ipscheck"],
        help="Probe sticky sessions and score exit IPs with IPQS",
    )
    _add_proxy_flags(ips_p)
    ips_p.add_argument("-n", "--sessions", type=int, default=10)
    ips_p.add_argument("-w", "--workers", type=int, default=10)
    ips_p.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=50,
        help="Clean if fraud score < threshold (default: 50)",
    )
    ips_p.set_defaults(func=cmd_ips_check)

    ip_p = sub.add_parser(
        "ip-check",
        aliases=["ipcheck"],
        help="IPQS lookup for IP address(es)",
    )
    ip_p.add_argument("ips", nargs="+", help="IP address(es) to check")
    ip_p.set_defaults(func=cmd_ip_check)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
