#!/usr/bin/env python3
"""
OTP Catcher - Retrieve OTPs from hyas-mail Cloudflare Worker

Usage:
  python otp_catcher.py get <email>           # Get OTP for email (returns immediately)
  python otp_catcher.py wait <email>         # Poll until OTP arrives (default 120s timeout)
  python otp_catcher.py wait <email> -t 60  # Custom timeout
  python otp_catcher.py list                 # List recent emails from D1
  python otp_catcher.py list -r user@hyas.site  # Filter by recipient
  python otp_catcher.py show <id>            # Show full email body

Examples:
  python otp_catcher.py wait cursor123@hyas.site
  python otp_catcher.py get verify@hyas.site
"""

import requests
import time
import sys
import json
from pathlib import Path
from typing import Optional

# --- Config ---
CONFIG_PATH = Path(__file__).parent / "config.json"
with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)
WORKER_URL = CONFIG["worker_url"]


# --- API helpers ---

def get_otp(email: str) -> Optional[dict]:
    """Get OTP from KV for a specific email. Returns None if not found or expired."""
    resp = requests.get(f"{WORKER_URL}/otp", params={"email": email})
    if resp.status_code == 200:
        return resp.json()
    return None


def wait_for_otp(email: str, timeout: int = 120, interval: int = 3) -> Optional[str]:
    """
    Poll KV until OTP arrives for the given email.
    Useful for automation: start signup, then call this to block until OTP is received.
    """
    print(f"Waiting for OTP at {email}...")
    start = time.time()
    
    while time.time() - start < timeout:
        data = get_otp(email)
        if data:
            otp = data.get("otp")
            print(f"OTP received: {otp}")
            return otp
        
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] No OTP yet, checking again in {interval}s...")
        time.sleep(interval)
    
    print(f"Timeout after {timeout}s - no OTP received")
    return None


def list_emails(limit: int = 10, recipient: str = None) -> list:
    """List recent emails from D1. Optionally filter by recipient."""
    params = {"limit": limit}
    if recipient:
        params["recipient"] = recipient
    
    resp = requests.get(f"{WORKER_URL}/emails", params=params)
    if resp.status_code == 200:
        return resp.json()
    return []


def get_email(email_id: int) -> Optional[dict]:
    """Get a single email by ID, including raw_body."""
    resp = requests.get(f"{WORKER_URL}/emails/{email_id}")
    if resp.status_code == 200:
        return resp.json()
    return None


def print_emails(emails: list):
    """Pretty-print email list to stdout."""
    if not emails:
        print("No emails found.")
        return
    
    print(f"\n{'ID':<5} {'Recipient':<30} {'OTP':<8} {'Received':<20}")
    print("-" * 70)
    for e in emails:
        print(f"{e['id']:<5} {e['recipient']:<30} {e.get('otp') or '-':<8} {e['received_at'][:19]}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="OTP Catcher - Retrieve OTPs from hyas-mail",
        epilog="See module docstring for usage examples.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # get command
    get_parser = subparsers.add_parser("get", help="Get OTP for email")
    get_parser.add_argument("email", help="Email address (e.g., test@hyas.site)")
    
    # wait command
    wait_parser = subparsers.add_parser("wait", help="Wait for OTP to arrive")
    wait_parser.add_argument("email", help="Email address (e.g., test@hyas.site)")
    wait_parser.add_argument("-t", "--timeout", type=int, default=120, help="Timeout in seconds (default: 120)")
    wait_parser.add_argument("-i", "--interval", type=int, default=3, help="Check interval in seconds (default: 3)")
    
    # list command
    list_parser = subparsers.add_parser("list", help="List recent emails")
    list_parser.add_argument("-n", "--limit", type=int, default=10, help="Number of emails (default: 10)")
    list_parser.add_argument("-r", "--recipient", help="Filter by recipient email")
    
    # show command
    show_parser = subparsers.add_parser("show", help="Show single email with full body")
    show_parser.add_argument("id", type=int, help="Email ID")
    
    args = parser.parse_args()
    
    if args.command == "get":
        data = get_otp(args.email)
        if data:
            print(f"OTP: {data['otp']}")
            print(f"From: {data['from']}")
            print(f"Subject: {data['subject']}")
            print(f"Received: {data['timestamp']}")
        else:
            print(f"No OTP found for {args.email}")
            sys.exit(1)
    
    elif args.command == "wait":
        otp = wait_for_otp(args.email, args.timeout, args.interval)
        if otp:
            print(otp)
        else:
            sys.exit(1)
    
    elif args.command == "list":
        emails = list_emails(args.limit, args.recipient)
        print_emails(emails)
    
    elif args.command == "show":
        email = get_email(args.id)
        if email:
            print(f"ID: {email['id']}")
            print(f"To: {email['recipient']}")
            print(f"From: {email['sender']}")
            print(f"Subject: {email['subject']}")
            print(f"OTP: {email.get('otp') or 'N/A'}")
            print(f"Received: {email['received_at']}")
            print(f"\n--- Body ---\n{email.get('raw_body', '')[:2000]}")
        else:
            print(f"Email {args.id} not found")
            sys.exit(1)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
