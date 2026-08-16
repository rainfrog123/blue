#!/usr/bin/env python3
"""
Use a HeroSMS number - manual purchase or most recent active.

Usage:
  python use_manual_number.py              # use most recently active
  python use_manual_number.py +447718920297
  python use_manual_number.py --id 155278024
"""

import sys
import time
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from herosms import (
    get_active_activations,
    get_status,
    get_status_v2,
    mark_ready,
    complete,
    cancel,
    request_resend,
)


def get_most_recent_activation() -> dict | None:
    """Return the most recently activated number (highest activationId)."""
    result = get_active_activations(limit=100)
    if result.get("status") != "success":
        return None
    data = result.get("data", [])
    if not data:
        return None
    return max(data, key=lambda a: int(a.get("activationId", 0)))


def find_activation_by_phone(phone: str) -> dict | None:
    """Find active activation by phone number (with or without +)."""
    phone = str(phone).replace("+", "").replace(" ", "").strip()
    result = get_active_activations(limit=100)
    if result.get("status") != "success":
        return None
    for act in result.get("data", []):
        act_phone = str(act.get("phoneNumber", "")).replace("+", "").replace(" ", "")
        if act_phone == phone:
            return act
    return None


def poll_for_sms(activation_id: int, interval: int = 5, timeout: int = 300) -> str | None:
    """Poll until SMS received or timeout. Returns code or None."""
    start = time.time()
    while time.time() - start < timeout:
        status = get_status(activation_id)
        if status.startswith("STATUS_OK:"):
            return status.split(":", 1)[1]
        if status == "STATUS_CANCEL":
            return None
        time.sleep(interval)
    return None


def main():
    parser = argparse.ArgumentParser(description="Use HeroSMS number from manual purchase")
    parser.add_argument("phone", nargs="?", help="Phone number (e.g. +447718920297 or 447718920297)")
    parser.add_argument("--id", type=int, help="Activation ID (if known)")
    parser.add_argument("--ready", action="store_true", help="Mark ready to receive SMS")
    parser.add_argument("--poll", action="store_true", help="Poll for SMS code until received")
    parser.add_argument("--complete", action="store_true", help="Complete activation (after getting code)")
    parser.add_argument("--cancel", action="store_true", help="Cancel and refund")
    parser.add_argument("--resend", action="store_true", help="Request SMS resend")
    parser.add_argument("--status", action="store_true", help="Show current status")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval seconds (default 5)")
    parser.add_argument("--timeout", type=int, default=300, help="Poll timeout seconds (default 300)")
    args = parser.parse_args()

    activation_id = args.id
    phone = args.phone

    if not activation_id and not phone:
        # Use most recently active
        act = get_most_recent_activation()
        if not act:
            print("Error: No active activations found")
            sys.exit(1)
        activation_id = int(act["activationId"])
        phone = act["phoneNumber"]
        print(f"Using most recent: +{phone} (id={activation_id})")
    elif not activation_id and phone:
        act = find_activation_by_phone(phone)
        if not act:
            print(f"Error: No active activation found for {phone}")
            print("Active activations:")
            result = get_active_activations(limit=20)
            for a in result.get("data", []):
                print(f"  {a['activationId']}: +{a['phoneNumber']} ({a['serviceCode']})")
            sys.exit(1)
        activation_id = int(act["activationId"])
        print(f"Found: activation_id={activation_id}, +{act['phoneNumber']}")

    if args.ready:
        mark_ready(activation_id)
        print("Marked ready to receive SMS")

    if args.resend:
        request_resend(activation_id)
        print("Requested SMS resend")

    if args.status:
        status = get_status(activation_id)
        print(f"Status: {status}")
        try:
            v2 = get_status_v2(activation_id)
            if v2.get("sms"):
                print(f"SMS: {v2['sms']}")
        except Exception:
            pass

    if args.poll:
        mark_ready(activation_id)
        print("Polling for SMS...")
        code = poll_for_sms(activation_id, args.interval, args.timeout)
        if code:
            print(f"Code: {code}")
            complete(activation_id)
            print("Activation completed")
        else:
            print("Timeout or cancelled - no code received")

    if args.complete:
        complete(activation_id)
        print("Activation completed")

    if args.cancel:
        cancel(activation_id)
        print("Cancelled (refunded)")

    if not any([args.ready, args.resend, args.status, args.poll, args.complete, args.cancel]):
        # Default: show status
        status = get_status(activation_id)
        print(f"Status: {status}")


if __name__ == "__main__":
    main()
