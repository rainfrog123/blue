#!/usr/bin/env python3
"""
OctoBrowser CLI - Main Entry Point

Manage OctoBrowser app and profiles.

Usage:
    python cli.py launch                   # Start OctoBrowser app
    python cli.py setup                    # One-time environment setup
    python cli.py status                   # Check if running
    python cli.py list                     # List profiles
    python cli.py create "Name"            # Create profile
    python cli.py start UUID               # Start profile
    python cli.py stop UUID                # Stop profile
"""

import argparse
import os
import sys
import time
import subprocess
import requests

# Add auto/ for imports
_octo_dir = os.path.dirname(os.path.abspath(__file__))
_auto_dir = os.path.join(_octo_dir, "auto")
if _auto_dir not in sys.path:
    sys.path.insert(0, _auto_dir)

from config import OCTO_APPIMAGE, OCTO_DEFAULT_PORT
from api_cli import register_api_commands


# =============================================================================
# Launch & Setup
# =============================================================================

def cmd_launch(args):
    """Start OctoBrowser app"""
    port = getattr(args, "port", None) or OCTO_DEFAULT_PORT
    octo_dir = os.path.expanduser("~/.Octo Browser")
    os.makedirs(octo_dir, exist_ok=True)
    with open(os.path.join(octo_dir, "local_port"), "w") as f:
        f.write(port)

    if not os.path.exists(OCTO_APPIMAGE):
        print(f"Error: AppImage not found: {OCTO_APPIMAGE}")
        return 1

    print(f"Starting OctoBrowser on :1 (port {port})...")

    env = os.environ.copy()
    env["DISPLAY"] = ":1"
    env["OCTO_EXTRA_ARGS"] = "--no-sandbox"
    env["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu-sandbox"

    subprocess.Popen(
        [OCTO_APPIMAGE, "--no-sandbox"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        cwd=os.path.dirname(OCTO_APPIMAGE) or "/"
    )

    for i in range(30):
        time.sleep(1)
        try:
            resp = requests.get(f"http://localhost:{port}/api/v2/client/themes", timeout=2)
            if resp.status_code == 200 and resp.json().get("success"):
                print(f"✓ OctoBrowser running. API: http://localhost:{port}")
                return 0
        except Exception:
            pass
        if (i + 1) % 5 == 0:
            print(f"  Waiting... ({i+1}s)")

    print("Timeout. Check: cli status")
    return 1


def cmd_setup(args):
    """One-time environment setup"""
    print("=== OctoBrowser Linux Setup ===\n")

    steps = [
        ("Installing unzip...", "apt update && apt install -y unzip"),
        ("Disabling AppArmor...", "systemctl stop apparmor && systemctl disable apparmor"),
        ("Removing AppArmor...", "apt remove -y apparmor"),
    ]

    for i, (msg, cmd) in enumerate(steps, 1):
        print(f"[{i}/{len(steps)}] {msg}")
        try:
            subprocess.run(["sudo", "bash", "-c", cmd], check=True, capture_output=not args.verbose)
        except subprocess.CalledProcessError as e:
            print(f"  Error: {e}")
            if not args.force:
                return 1

    print("\n=== Setup Complete ===")
    print("A reboot may be required for changes to take effect.")

    if not args.no_reboot:
        try:
            answer = input("Reboot now? [y/N]: ").strip().lower()
            if answer == "y":
                subprocess.run(["sudo", "reboot"], check=False)
        except EOFError:
            pass

    return 0


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="OctoBrowser CLI")
    sub = parser.add_subparsers(dest="command")

    # Launch & setup commands
    p = sub.add_parser("launch", aliases=["start-app"])
    p.add_argument("--port", default=OCTO_DEFAULT_PORT, help="Local API port")
    p.set_defaults(func=cmd_launch)

    p = sub.add_parser("setup", aliases=["env-setup"])
    p.add_argument("--no-reboot", action="store_true", help="Skip reboot prompt")
    p.add_argument("--force", action="store_true", help="Continue on errors")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_setup)

    # Register API commands from api_cli
    register_api_commands(sub, OCTO_DEFAULT_PORT)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
