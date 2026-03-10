#!/usr/bin/env python3
"""
OctoBrowser HID Spoofing Tool

Generates a new machine-id and clears OctoBrowser storage to bypass
hardware fingerprint-based device binding.

Usage:
    python3 spoof_hid.py              # Generate random HID
    python3 spoof_hid.py <32-hex>     # Set specific HID
    python3 spoof_hid.py --restore    # Restore original HID
    python3 spoof_hid.py --info       # Show current HID info
"""

import os
import sys
import uuid
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Optional


# Configuration
MACHINE_ID_FILE = Path("/etc/machine-id")
BACKUP_FILE = Path("/etc/machine-id.backup")
OCTO_DIR = Path.home() / ".Octo Browser"

# Files to remove (encrypted with HID)
OCTO_STORAGE_FILES = [
    "local.data",
    "localpersist.data",
]

# Optional: Also clear these for full reset
OCTO_CACHE_DIRS = [
    # "bcache",
    # "webviewengine",
]


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


def print_header():
    print(f"{Colors.CYAN}")
    print("=" * 50)
    print("  OctoBrowser HID Spoofing Tool")
    print("=" * 50)
    print(f"{Colors.NC}")


def print_status(msg: str):
    print(f"{Colors.GREEN}[+]{Colors.NC} {msg}")


def print_warning(msg: str):
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")


def print_error(msg: str):
    print(f"{Colors.RED}[-]{Colors.NC} {msg}")


def get_current_hid() -> Optional[str]:
    """Read current machine-id"""
    try:
        return MACHINE_ID_FILE.read_text().strip()
    except Exception:
        return None


def get_backup_hid() -> Optional[str]:
    """Read backup machine-id"""
    try:
        return BACKUP_FILE.read_text().strip()
    except Exception:
        return None


def generate_random_hid() -> str:
    """Generate a random 32-character hex string"""
    return uuid.uuid4().hex


def validate_hid(hid: str) -> bool:
    """Validate HID format (32 hex characters)"""
    if len(hid) != 32:
        return False
    try:
        int(hid, 16)
        return True
    except ValueError:
        return False


def run_sudo(cmd: list) -> bool:
    """Run a command with sudo"""
    try:
        subprocess.run(["sudo"] + cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def backup_hid():
    """Backup current machine-id"""
    if BACKUP_FILE.exists():
        print_warning(f"Backup already exists: {BACKUP_FILE}")
        return True
    
    print_status("Backing up original machine-id...")
    if run_sudo(["cp", str(MACHINE_ID_FILE), str(BACKUP_FILE)]):
        print_status(f"Backup saved to: {BACKUP_FILE}")
        return True
    else:
        print_error("Failed to create backup")
        return False


def set_hid(new_hid: str) -> bool:
    """Set new machine-id"""
    print_status(f"Setting new machine-id: {new_hid}")
    
    # Write to temp file first
    temp_file = Path("/tmp/new_machine_id")
    temp_file.write_text(new_hid + "\n")
    
    # Copy with sudo
    if not run_sudo(["cp", str(temp_file), str(MACHINE_ID_FILE)]):
        print_error("Failed to set machine-id")
        return False
    
    # Set permissions
    run_sudo(["chmod", "444", str(MACHINE_ID_FILE)])
    
    # Cleanup
    temp_file.unlink()
    
    return True


def clear_octo_storage():
    """Remove OctoBrowser encrypted storage files"""
    print_status("Clearing OctoBrowser storage...")
    
    if not OCTO_DIR.exists():
        print_warning(f"OctoBrowser directory not found: {OCTO_DIR}")
        return
    
    # Remove storage files
    for filename in OCTO_STORAGE_FILES:
        filepath = OCTO_DIR / filename
        if filepath.exists():
            filepath.unlink()
            print_status(f"Removed: {filename}")
    
    # Remove cache directories (optional)
    for dirname in OCTO_CACHE_DIRS:
        dirpath = OCTO_DIR / dirname
        if dirpath.exists():
            shutil.rmtree(dirpath)
            print_status(f"Removed: {dirname}/")


def kill_octobrowser():
    """Kill any running OctoBrowser processes"""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "OctoBrowser"],
            capture_output=True
        )
        if result.returncode == 0:
            print_status("Stopping OctoBrowser...")
            subprocess.run(["pkill", "-f", "OctoBrowser"], check=False)
            import time
            time.sleep(2)
    except Exception:
        pass


def restore_hid():
    """Restore original machine-id from backup"""
    if not BACKUP_FILE.exists():
        print_error(f"No backup file found: {BACKUP_FILE}")
        return False
    
    print_status("Restoring original machine-id...")
    
    if not run_sudo(["cp", str(BACKUP_FILE), str(MACHINE_ID_FILE)]):
        print_error("Failed to restore machine-id")
        return False
    
    run_sudo(["chmod", "444", str(MACHINE_ID_FILE)])
    
    print_status(f"Restored from: {BACKUP_FILE}")
    print_status(f"Current HID: {get_current_hid()}")
    
    print_warning("Remember to clear OctoBrowser storage after restoring!")
    print(f"  rm -f ~/.Octo\\ Browser/local.data ~/.Octo\\ Browser/localpersist.data")
    
    return True


def show_info():
    """Display current HID information"""
    print(f"\n{Colors.BLUE}Current Status:{Colors.NC}")
    print(f"  Machine ID File: {MACHINE_ID_FILE}")
    print(f"  Current HID:     {get_current_hid() or 'not found'}")
    print(f"  Backup File:     {BACKUP_FILE}")
    
    backup = get_backup_hid()
    if backup:
        print(f"  Backup HID:      {backup}")
    
    print(f"  OctoBrowser Dir: {OCTO_DIR}")
    
    if OCTO_DIR.exists():
        storage_files = []
        for f in OCTO_STORAGE_FILES:
            if (OCTO_DIR / f).exists():
                size = (OCTO_DIR / f).stat().st_size
                storage_files.append(f"{f} ({size} bytes)")
        if storage_files:
            print(f"  Storage Files:   {', '.join(storage_files)}")
    print()


def confirm(msg: str) -> bool:
    """Ask for confirmation"""
    response = input(f"{msg} [y/N] ").strip().lower()
    return response in ('y', 'yes')


def main():
    parser = argparse.ArgumentParser(
        description="OctoBrowser HID Spoofing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Random HID
  %(prog)s 00000000000000000000000000000001   # Specific HID
  %(prog)s --restore                          # Restore backup
  %(prog)s --info                             # Show info
        """
    )
    parser.add_argument('hid', nargs='?', help='Specific HID (32 hex chars)')
    parser.add_argument('--restore', '-r', action='store_true',
                       help='Restore original HID from backup')
    parser.add_argument('--info', '-i', action='store_true',
                       help='Show current HID information')
    parser.add_argument('--yes', '-y', action='store_true',
                       help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    print_header()
    
    # Handle --info
    if args.info:
        show_info()
        return 0
    
    # Handle --restore
    if args.restore:
        if restore_hid():
            return 0
        return 1
    
    # Determine new HID
    if args.hid:
        if not validate_hid(args.hid):
            print_error("Invalid HID format. Must be 32 hexadecimal characters.")
            print_error("Example: 00000000000000000000000000000001")
            return 1
        new_hid = args.hid.lower()
    else:
        new_hid = generate_random_hid()
    
    # Show current state
    show_info()
    
    # Confirm action
    print(f"{Colors.YELLOW}This will:{Colors.NC}")
    print("  1. Backup current machine-id (if not already backed up)")
    print(f"  2. Set new machine-id: {new_hid}")
    print("  3. Kill OctoBrowser if running")
    print("  4. Clear OctoBrowser encrypted storage")
    print()
    
    if not args.yes and not confirm("Continue?"):
        print_warning("Aborted.")
        return 0
    
    print()
    
    # Execute spoofing
    if not backup_hid():
        return 1
    
    kill_octobrowser()
    
    if not set_hid(new_hid):
        return 1
    
    clear_octo_storage()
    
    # Show result
    print()
    print(f"{Colors.GREEN}{'=' * 50}")
    print("  HID Spoofing Complete!")
    print(f"{'=' * 50}{Colors.NC}")
    print()
    print(f"  Old HID: {get_backup_hid() or 'unknown'}")
    print(f"  New HID: {get_current_hid()}")
    print()
    print(f"{Colors.YELLOW}Next steps:{Colors.NC}")
    print("  1. Start OctoBrowser")
    print("  2. Log in with your account (new device will be registered)")
    print()
    print(f"{Colors.YELLOW}To restore original HID:{Colors.NC}")
    print(f"  python3 {sys.argv[0]} --restore")
    print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
