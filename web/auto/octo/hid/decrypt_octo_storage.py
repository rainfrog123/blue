#!/usr/bin/env python3
"""
OctoBrowser Storage Decryption Tool

Decrypts the local.data and localpersist.data files to view stored HID
and authentication state.

The encryption uses:
- Fernet (AES-128-CBC + HMAC-SHA256)
- PBKDF2 key derivation with machine HID as the password

Usage:
    python3 decrypt_octo_storage.py [--hid CUSTOM_HID]
"""

import os
import sys
import json
import base64
import hashlib
import argparse
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography library not installed")
    print("Run: pip install cryptography")
    sys.exit(1)


# OctoBrowser constants (from config.py analysis)
SECRET_KEY = "TeNtAcLeShErE___"
OCTO_APP_ID = "octo-c6cfa04f-4432-ae38-15bdc035170f"


def get_linux_hid() -> str:
    """Get the machine HID on Linux"""
    machine_id_path = "/etc/machine-id"
    try:
        with open(machine_id_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"Error reading {machine_id_path}: {e}")
        return None


def get_macos_hid() -> str:
    """Get the machine HID on macOS"""
    import subprocess
    try:
        result = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in result.split('\n'):
            if 'UUID' in line:
                # Extract UUID from line like: "IOPlatformUUID" = "XXXXXXXX-..."
                parts = line.split('"')
                for i, part in enumerate(parts):
                    if 'UUID' in part and i + 2 < len(parts):
                        return parts[i + 2]
    except Exception as e:
        print(f"Error getting macOS HID: {e}")
    return None


def get_windows_hid() -> str:
    """Get the machine HID on Windows"""
    import subprocess
    try:
        # Try PowerShell first
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        return result.strip()
    except Exception:
        try:
            # Fallback to WMIC
            result = subprocess.check_output(
                ["wmic", "csproduct", "get", "uuid"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            lines = result.strip().split('\n')
            if len(lines) > 1:
                return lines[1].strip()
        except Exception as e:
            print(f"Error getting Windows HID: {e}")
    return None


def get_system_hid() -> str:
    """Get the machine HID based on current platform"""
    import platform
    system = platform.system().lower()
    
    if system == 'linux':
        return get_linux_hid()
    elif system == 'darwin':
        return get_macos_hid()
    elif system == 'windows':
        return get_windows_hid()
    else:
        print(f"Unsupported platform: {system}")
        return None


def derive_fernet_key(password: str, salt: bytes = None) -> tuple:
    """
    Derive a Fernet key from password using PBKDF2
    Returns (key, salt) tuple
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # cryptography default
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def decrypt_fernet_data(encrypted_data: bytes, password: str) -> dict:
    """
    Decrypt Fernet-encrypted data
    OctoBrowser uses a simple Fernet format without header
    """
    try:
        # The data is base64-encoded Fernet token
        # Fernet uses the password hash directly as the key
        
        # Try direct Fernet decryption with password hash
        password_bytes = password.encode()
        
        # OctoBrowser's password hash method
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'',  # Empty salt for compatibility
            iterations=100000,
            backend=default_backend()
        )
        
        # Try different key derivation approaches
        attempts = [
            # Approach 1: Direct base64 of password hash
            base64.urlsafe_b64encode(hashlib.sha256(password_bytes).digest()),
            # Approach 2: PBKDF2 with empty salt
            # Approach 3: Direct password as key (padded/truncated)
            base64.urlsafe_b64encode(password_bytes.ljust(32, b'\0')[:32]),
        ]
        
        for key in attempts:
            try:
                f = Fernet(key)
                decrypted = f.decrypt(encrypted_data)
                return json.loads(decrypted)
            except Exception:
                continue
        
        # If none worked, try with standard cryptography approach
        # The key might be derived differently
        return None
        
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def analyze_storage_file(file_path: str, hid: str) -> dict:
    """Analyze and try to decrypt a storage file"""
    results = {
        'path': file_path,
        'exists': False,
        'size': 0,
        'encrypted': True,
        'decrypted_data': None,
        'analysis': []
    }
    
    if not os.path.exists(file_path):
        results['analysis'].append("File does not exist")
        return results
    
    results['exists'] = True
    results['size'] = os.path.getsize(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Check if it's base64 (Fernet format)
    try:
        decoded = base64.urlsafe_b64decode(data + b'==')  # Add padding
        results['analysis'].append(f"File is base64 encoded ({len(decoded)} bytes decoded)")
        
        # Check for Fernet signature
        if data.startswith(b'gAAAAAB'):
            results['analysis'].append("Detected Fernet encryption format")
    except Exception:
        results['analysis'].append("File is not base64 encoded")
    
    # Try decryption with various password combinations
    passwords_to_try = [
        hid,
        hid + SECRET_KEY,
        SECRET_KEY + hid,
        hashlib.sha256((hid + SECRET_KEY).encode()).hexdigest(),
        OCTO_APP_ID + hid,
    ]
    
    for pwd in passwords_to_try:
        result = decrypt_fernet_data(data, pwd)
        if result:
            results['decrypted_data'] = result
            results['analysis'].append(f"Successfully decrypted with password pattern")
            break
    
    if not results['decrypted_data']:
        results['analysis'].append("Could not decrypt with known password patterns")
        results['analysis'].append("The encryption key derivation may use additional parameters")
    
    return results


def print_hid_info(hid: str):
    """Print information about the HID"""
    print("\n" + "="*70)
    print("HARDWARE ID (HID) INFORMATION")
    print("="*70)
    print(f"  HID Value: {hid}")
    print(f"  HID Length: {len(hid)} characters")
    print(f"  HID SHA256: {hashlib.sha256(hid.encode()).hexdigest()[:32]}...")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="OctoBrowser Storage Decryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 decrypt_octo_storage.py
  python3 decrypt_octo_storage.py --hid "custom_machine_id_here"
  python3 decrypt_octo_storage.py --storage-dir "/path/to/.Octo Browser"
        """
    )
    parser.add_argument('--hid', help='Custom HID to use for decryption')
    parser.add_argument('--storage-dir', help='OctoBrowser storage directory',
                       default=os.path.expanduser("~/.Octo Browser"))
    parser.add_argument('--show-raw', action='store_true', 
                       help='Show raw encrypted data')
    args = parser.parse_args()
    
    print("="*70)
    print("OctoBrowser Storage Analysis Tool")
    print("="*70)
    
    # Get HID
    if args.hid:
        hid = args.hid
        print(f"\nUsing provided HID: {hid[:8]}...")
    else:
        hid = get_system_hid()
        if not hid:
            print("\nError: Could not determine system HID")
            print("Please provide HID manually with --hid option")
            sys.exit(1)
        print(f"\nDetected system HID: {hid}")
    
    print_hid_info(hid)
    
    # Check storage directory
    storage_dir = args.storage_dir
    if not os.path.isdir(storage_dir):
        print(f"Storage directory not found: {storage_dir}")
        print("OctoBrowser may not have been run yet.")
        sys.exit(1)
    
    print(f"Storage directory: {storage_dir}")
    print("\n" + "="*70)
    print("STORAGE FILES")
    print("="*70)
    
    # List all files in storage directory
    for item in os.listdir(storage_dir):
        item_path = os.path.join(storage_dir, item)
        if os.path.isfile(item_path):
            size = os.path.getsize(item_path)
            print(f"  {item}: {size} bytes")
    
    # Analyze specific storage files
    storage_files = [
        ('local.data', 'Session Storage'),
        ('localpersist.data', 'Persistent Storage'),
    ]
    
    for filename, description in storage_files:
        filepath = os.path.join(storage_dir, filename)
        
        print(f"\n{'='*70}")
        print(f"{description}: {filename}")
        print("="*70)
        
        if not os.path.exists(filepath):
            print("  [NOT FOUND]")
            continue
        
        results = analyze_storage_file(filepath, hid)
        
        print(f"  Size: {results['size']} bytes")
        print("  Analysis:")
        for note in results['analysis']:
            print(f"    - {note}")
        
        if results['decrypted_data']:
            print("\n  Decrypted Content:")
            print(json.dumps(results['decrypted_data'], indent=4))
        
        if args.show_raw:
            with open(filepath, 'rb') as f:
                raw = f.read()
            print(f"\n  Raw data (first 200 bytes):")
            print(f"    {raw[:200]}")
    
    # Print encryption information
    print("\n" + "="*70)
    print("ENCRYPTION DETAILS")
    print("="*70)
    print("""
  Algorithm: Fernet (AES-128-CBC + HMAC-SHA256)
  Key Derivation: PBKDF2-HMAC-SHA256
  
  Key Derivation Parameters:
    - Password: Machine HID (+ possible SECRET_KEY)
    - Salt: Embedded in encrypted data or fixed
    - Iterations: ~100,000-480,000
    
  SECRET_KEY found in code: "{}"
  APP_ID found in code: "{}"
  
  To fully decrypt, you may need to:
    1. Decompile config.py to get exact key derivation
    2. Check octo/helpers/encryption.py for password_hash()
    3. Check octo/helpers/storage.py for Storage class
""".format(SECRET_KEY, OCTO_APP_ID))
    
    # Print spoofing instructions
    print("\n" + "="*70)
    print("HID SPOOFING INSTRUCTIONS")
    print("="*70)
    print("""
  To spoof the hardware ID on Linux:
  
  1. Backup current machine-id:
     sudo cp /etc/machine-id /etc/machine-id.backup
     
  2. Create new machine-id:
     # Generate random
     sudo rm /etc/machine-id && sudo systemd-machine-id-setup
     
     # Or set specific value (32 hex characters)
     echo "00000000000000000000000000000001" | sudo tee /etc/machine-id
     
  3. Delete OctoBrowser storage (encrypted with old HID):
     rm -rf ~/.Octo\\ Browser/local.data
     rm -rf ~/.Octo\\ Browser/localpersist.data
     
  4. Restart OctoBrowser - it will create new storage with new HID
  
  Note: The HID is sent to OctoBrowser servers during authentication,
        so changing it will require re-authentication.
""")


if __name__ == '__main__':
    main()
