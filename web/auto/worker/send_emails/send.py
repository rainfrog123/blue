#!/usr/bin/env python3
"""
Send emails via Resend API or SMTP.

Usage:
  python send.py <from> <to> <subject> <body>
  python send.py <from> <to> <subject> -f body.txt
  python send.py <from> <to> <subject> -f body.html --html

Examples:
  python send.py test@hyas.space user@gmail.com "Hello" "This is a test email"
  python send.py test@hyas.space user@gmail.com "Newsletter" -f newsletter.html --html
"""

import requests
import smtplib
import sys
import os
import argparse
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent.parent / "linux" / "extra"))
from cred_loader import get_resend


def send_via_resend(from_addr: str, to_addr: str, subject: str, body: str, html: bool) -> tuple:
    api_key = os.environ.get("RESEND_API_KEY") or get_resend().get("api_key")
    if not api_key:
        return {"error": "RESEND_API_KEY not set"}, 400
    
    payload = {
        "from": from_addr,
        "to": [to_addr],
        "subject": subject,
    }
    if html:
        payload["html"] = body
    else:
        payload["text"] = body
    
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload
    )
    return resp.json(), resp.status_code


def send_email(from_addr: str, to_addr: str, subject: str, body: str, html: bool = False) -> tuple:
    return send_via_resend(from_addr, to_addr, subject, body, html)


def main():
    parser = argparse.ArgumentParser(description="Send email via Resend")
    parser.add_argument("from_addr", metavar="from", help="Sender email")
    parser.add_argument("to_addr", metavar="to", help="Recipient email")
    parser.add_argument("subject", help="Email subject")
    parser.add_argument("body", nargs="?", help="Email body (text)")
    parser.add_argument("-f", "--file", help="Read body from file")
    parser.add_argument("--html", action="store_true", help="Send as HTML email")
    
    args = parser.parse_args()
    
    if args.file:
        body = Path(args.file).read_text()
    elif args.body:
        body = args.body
    else:
        print("Error: Provide body as argument or use -f <file>")
        sys.exit(1)
    
    print(f"Sending email...")
    print(f"  From: {args.from_addr}")
    print(f"  To: {args.to_addr}")
    print(f"  Subject: {args.subject}")
    
    result, status = send_email(args.from_addr, args.to_addr, args.subject, body, args.html)
    
    if result.get("id"):
        print(f"\nEmail sent! ID: {result['id']}")
    else:
        import json
        print(f"\nFailed (status {status}):")
        print(json.dumps(result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
