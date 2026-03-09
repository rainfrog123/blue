#!/usr/bin/env python3
"""
OctoBrowser CLI - Main Entry Point

Manage OctoBrowser app, HID spoofing, and profiles.

Usage:
    python cli.py launch                   # Start OctoBrowser app
    python cli.py setup                    # One-time environment setup
    python cli.py hid                      # Show machine-id info
    python cli.py hid spoof                # Spoof with random HID
    python cli.py hid restore              # Restore original HID
"""

import argparse
import os
import re
import sys
import time
import subprocess
import uuid
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
# HID (Machine-ID) Management
# =============================================================================

MACHINE_ID = "/etc/machine-id"
MACHINE_ID_BAK = "/etc/machine-id.backup"


def hid_get():
    """Get current machine-id"""
    try:
        with open(MACHINE_ID) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def hid_valid(hid):
    """Check if HID is valid (32 hex chars)"""
    return bool(hid and len(hid) == 32 and re.match(r'^[0-9a-fA-F]+$', hid))


def hid_gen():
    """Generate random HID"""
    return uuid.uuid4().hex


def cmd_hid_info(args):
    """Show HID info"""
    print("\nHID Status")
    print("=" * 40)
    print(f"  machine-id : {hid_get() or 'not found'}")
    if os.path.exists(MACHINE_ID_BAK):
        with open(MACHINE_ID_BAK) as f:
            print(f"  backup     : {f.read().strip()}")
    octo_dir = os.path.expanduser("~/.Octo Browser")
    print(f"  octo dir   : {octo_dir}")
    print(f"  octo bin   : {OCTO_APPIMAGE}")
    print()
    return 0


def cmd_hid_spoof(args):
    """Spoof machine-id"""
    new_hid = args.hid if args.hid else hid_gen()
    new_hid = new_hid.lower()

    if not hid_valid(new_hid):
        print(f"Error: Invalid HID '{new_hid}' - must be 32 hex chars")
        return 1

    old_hid = hid_get()
    print(f"\nCurrent: {old_hid}")
    print(f"New:     {new_hid}")

    if not args.force:
        print("\nThis will:")
        print("  1. Backup current machine-id")
        print("  2. Set new machine-id")
        print("  3. Kill OctoBrowser")
        print("  4. Clear OctoBrowser storage")
        try:
            if input("\nContinue? [y/N]: ").strip().lower() != "y":
                print("Aborted.")
                return 0
        except EOFError:
            return 0

    # Backup
    if not os.path.exists(MACHINE_ID_BAK):
        subprocess.run(["sudo", "cp", MACHINE_ID, MACHINE_ID_BAK], check=True)
        print(f"✓ Backed up to {MACHINE_ID_BAK}")

    # Kill OctoBrowser
    subprocess.run(["pkill", "-f", "OctoBrowser"], capture_output=True)
    time.sleep(1)

    # Set new HID
    subprocess.run(f"echo '{new_hid}' | sudo tee {MACHINE_ID} > /dev/null", shell=True, check=True)
    subprocess.run(["sudo", "chmod", "444", MACHINE_ID], check=True)
    print(f"✓ Machine-id set: {new_hid}")

    # Clear OctoBrowser storage
    octo_dir = os.path.expanduser("~/.Octo Browser")
    if os.path.isdir(octo_dir):
        for f in ["local.data", "localpersist.data"]:
            path = os.path.join(octo_dir, f)
            if os.path.exists(path):
                os.remove(path)
                print(f"✓ Removed {f}")
        port_file = os.path.join(octo_dir, "local_port")
        with open(port_file, "w") as f:
            f.write(OCTO_DEFAULT_PORT)
        print(f"✓ Set local_port to {OCTO_DEFAULT_PORT}")

    print(f"\n✓ Done! {old_hid} → {new_hid}")
    print(f"\nRestore with: cli.py hid restore")
    return 0


def cmd_hid_restore(args):
    """Restore original machine-id"""
    if not os.path.exists(MACHINE_ID_BAK):
        print(f"Error: No backup found at {MACHINE_ID_BAK}")
        return 1

    subprocess.run(["sudo", "cp", MACHINE_ID_BAK, MACHINE_ID], check=True)
    subprocess.run(["sudo", "chmod", "444", MACHINE_ID], check=True)
    print(f"✓ Restored: {hid_get()}")
    print("Run 'cli.py hid clear' to wipe OctoBrowser storage")
    return 0


def cmd_hid_clear(args):
    """Clear OctoBrowser storage"""
    octo_dir = os.path.expanduser("~/.Octo Browser")
    if not os.path.isdir(octo_dir):
        print(f"OctoBrowser dir not found: {octo_dir}")
        return 1

    # Kill first
    subprocess.run(["pkill", "-f", "OctoBrowser"], capture_output=True)
    time.sleep(1)

    for f in ["local.data", "localpersist.data"]:
        path = os.path.join(octo_dir, f)
        if os.path.exists(path):
            os.remove(path)
            print(f"✓ Removed {f}")

    port_file = os.path.join(octo_dir, "local_port")
    with open(port_file, "w") as f:
        f.write(OCTO_DEFAULT_PORT)
    print(f"✓ Set local_port to {OCTO_DEFAULT_PORT}")
    return 0


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="OctoBrowser CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Launch & setup commands
    p = sub.add_parser("launch", aliases=["start-app"], help="Start OctoBrowser app")
    p.add_argument("--port", default=OCTO_DEFAULT_PORT, help="Local API port")
    p.set_defaults(func=cmd_launch)

    p = sub.add_parser("setup", aliases=["env-setup"], help="One-time environment setup")
    p.add_argument("--no-reboot", action="store_true", help="Skip reboot prompt")
    p.add_argument("--force", action="store_true", help="Continue on errors")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_setup)

    # HID commands
    hid_parser = sub.add_parser("hid", help="Machine-ID management")
    hid_sub = hid_parser.add_subparsers(dest="hid_command", metavar="ACTION")

    hid_sub.add_parser("info", help="Show HID info").set_defaults(func=cmd_hid_info)

    p = hid_sub.add_parser("spoof", help="Spoof machine-id")
    p.add_argument("hid", nargs="?", help="32-char hex HID (random if omitted)")
    p.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    p.set_defaults(func=cmd_hid_spoof)

    hid_sub.add_parser("restore", help="Restore original machine-id").set_defaults(func=cmd_hid_restore)
    hid_sub.add_parser("clear", help="Clear OctoBrowser storage").set_defaults(func=cmd_hid_clear)

    hid_parser.set_defaults(func=cmd_hid_info)

    # Register API commands from api_cli
    register_api_commands(sub, OCTO_DEFAULT_PORT)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
