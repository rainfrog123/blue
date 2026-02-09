#!/usr/bin/env python3
"""
OctoBrowser Storage Decryption Tool

Decrypts the local.data and localpersist.data files to view stored HID
and authentication state.

Based on Ghidra reverse engineering analysis:
- Encryption: Fernet (AES-128-CBC + HMAC-SHA256)
- Key Derivation: PBKDF2-HMAC-SHA256
- Iterations: 100,000 (found in octo_crypto/encryption/ciphers/fernet.pyc)
- Password: Machine HID (from /etc/machine-id on Linux)
- Salt: 16 bytes, either embedded in file header or generated per-encryption

Usage:
    python3 decrypt_storage.py [--hid CUSTOM_HID]
"""

import os
import sys
import json
import base64
import hashlib
import argparse
import struct
import zlib
from pathlib import Path
from io import BytesIO

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography library not installed")
    print("Run: pip install cryptography")
    sys.exit(1)


# OctoBrowser constants (from Ghidra analysis of config.pyc)
SECRET_KEY = "TeNtAcLeShErE___"
OCTO_APP_ID = "octo-c6cfa04f-4432-ae38-15bdc035170f"

# Key derivation parameters (from Ghidra analysis of fernet.pyc)
PBKDF2_ITERATIONS = 100000
PBKDF2_KEY_LENGTH = 32
PBKDF2_SALT_LENGTH = 16


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


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet key from password using PBKDF2
    
    Based on Ghidra analysis of octo_crypto/encryption/ciphers/fernet.pyc:
    - Algorithm: SHA256
    - Length: 32 bytes
    - Iterations: 100,000
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def password_hash(password: str, salt: bytes) -> str:
    """
    OctoBrowser's password_hash function from octo/helpers/encryption.py
    
    From Ghidra analysis:
    - Uses PBKDF2HMAC with SHA256
    - 100,000 iterations
    - Returns base64 encoded key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()


def decrypt_fernet_legacy(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypt legacy Fernet format (compat mode)
    
    The legacy format uses:
    - Raw Fernet token (starts with gAAAAAB)
    - Salt passed separately (stored elsewhere or fixed)
    """
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_data)


def decrypt_fernet_new_format(data: bytes, password: str) -> tuple:
    """
    Decrypt new file format with embedded metadata
    
    From Ghidra analysis of octo_crypto/encryption/encryptor.pyc:
    
    File format:
        * 2 bytes (i16) - format version
        * 2 bytes (i16) - cipher type length
        * N bytes - cipher type string
        * 4 bytes (i32) - salt length
        * N bytes - salt value
        * 4 bytes (i32) - metadata length
        * N bytes - metadata (JSON)
        * rest is ciphertext
    """
    stream = BytesIO(data)
    
    # Read format version
    version = struct.unpack('>h', stream.read(2))[0]
    
    # Read cipher type
    cipher_type_len = struct.unpack('>h', stream.read(2))[0]
    cipher_type = stream.read(cipher_type_len).decode().strip()
    
    # Read salt
    salt_len = struct.unpack('>i', stream.read(4))[0]
    salt = stream.read(salt_len)
    
    # Read metadata
    metadata_len = struct.unpack('>i', stream.read(4))[0]
    metadata = json.loads(stream.read(metadata_len).decode()) if metadata_len > 0 else {}
    
    # Rest is ciphertext
    ciphertext = stream.read()
    
    # Decrypt based on cipher type
    if cipher_type in ('fernet', 'fernet_meta'):
        key = derive_fernet_key(password, salt)
        f = Fernet(key)
        decrypted = f.decrypt(ciphertext)
        return decrypted, metadata, cipher_type
    
    raise ValueError(f"Unknown cipher type: {cipher_type}")


def decrypt_fernet_data(encrypted_data: bytes, password: str) -> dict:
    """
    Decrypt Fernet-encrypted data using OctoBrowser's exact method
    
    Based on Ghidra reverse engineering:
    - Password is the machine HID directly
    - Salt is extracted from the Fernet token itself (first 16 bytes after version)
    - Or uses legacy compat mode with external salt
    """
    errors = []
    
    # Check if it's raw Fernet token (legacy format)
    if encrypted_data.startswith(b'gAAAAAB'):
        # Fernet token format:
        # - Version (1 byte): 0x80
        # - Timestamp (8 bytes)
        # - IV (16 bytes)
        # - Ciphertext (variable)
        # - HMAC (32 bytes)
        
        # The salt is NOT in the token - it's stored/derived separately
        # Try different salt strategies
        
        salt_strategies = [
            # Strategy 1: Use HID itself as salt (first 16 bytes)
            password.encode()[:PBKDF2_SALT_LENGTH].ljust(PBKDF2_SALT_LENGTH, b'\x00'),
            # Strategy 2: Use SECRET_KEY as salt
            SECRET_KEY.encode()[:PBKDF2_SALT_LENGTH].ljust(PBKDF2_SALT_LENGTH, b'\x00'),
            # Strategy 3: SHA256 of HID as salt
            hashlib.sha256(password.encode()).digest()[:PBKDF2_SALT_LENGTH],
            # Strategy 4: SHA256 of HID+SECRET as salt
            hashlib.sha256((password + SECRET_KEY).encode()).digest()[:PBKDF2_SALT_LENGTH],
            # Strategy 5: Empty salt
            b'\x00' * PBKDF2_SALT_LENGTH,
            # Strategy 6: Fixed known salt patterns
            b'octobrowser_salt'[:PBKDF2_SALT_LENGTH].ljust(PBKDF2_SALT_LENGTH, b'\x00'),
            # Strategy 7: APP_ID based salt
            hashlib.sha256(OCTO_APP_ID.encode()).digest()[:PBKDF2_SALT_LENGTH],
        ]
        
        for i, salt in enumerate(salt_strategies):
            try:
                decrypted = decrypt_fernet_legacy(encrypted_data, password, salt)
                # Try to decompress if it's zlib compressed
                try:
                    decrypted = zlib.decompress(decrypted)
                except:
                    pass
                return json.loads(decrypted), f"Strategy {i+1}"
            except Exception as e:
                errors.append(f"Strategy {i+1}: {str(e)[:50]}")
                continue
    
    # Try new format with embedded metadata
    else:
        try:
            decrypted, metadata, cipher_type = decrypt_fernet_new_format(encrypted_data, password)
            try:
                decrypted = zlib.decompress(decrypted)
            except:
                pass
            return json.loads(decrypted), f"New format ({cipher_type})"
        except Exception as e:
            errors.append(f"New format: {str(e)[:50]}")
    
    # Return errors for debugging
    return None, errors


def analyze_storage_file(file_path: str, hid: str) -> dict:
    """Analyze and try to decrypt a storage file"""
    results = {
        'path': file_path,
        'exists': False,
        'size': 0,
        'encrypted': True,
        'decrypted_data': None,
        'analysis': [],
        'decryption_method': None
    }
    
    if not os.path.exists(file_path):
        results['analysis'].append("File does not exist")
        return results
    
    results['exists'] = True
    results['size'] = os.path.getsize(file_path)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Detect format
    if data.startswith(b'gAAAAAB'):
        results['analysis'].append("Detected legacy Fernet format (starts with gAAAAAB)")
    elif len(data) > 4:
        # Check for new format
        try:
            version = struct.unpack('>h', data[:2])[0]
            if 0 < version < 100:  # Reasonable version number
                results['analysis'].append(f"Detected new format (version {version})")
        except:
            pass
    
    # Check if it's base64 (Fernet format)
    try:
        decoded = base64.urlsafe_b64decode(data + b'==')
        results['analysis'].append(f"Base64 decoded size: {len(decoded)} bytes")
    except Exception:
        results['analysis'].append("File is not pure base64 encoded")
    
    # Try decryption with various password combinations
    # Based on Ghidra analysis of storage.py: passphrase = hid
    passwords_to_try = [
        (hid, "HID only"),
        (hid + SECRET_KEY, "HID + SECRET_KEY"),
        (SECRET_KEY + hid, "SECRET_KEY + HID"),
        (hashlib.sha256((hid + SECRET_KEY).encode()).hexdigest(), "SHA256(HID+SECRET)"),
        (OCTO_APP_ID + hid, "APP_ID + HID"),
        (hid.lower(), "HID lowercase"),
        (hid.upper(), "HID uppercase"),
    ]
    
    for pwd, desc in passwords_to_try:
        result, method = decrypt_fernet_data(data, pwd)
        if result and isinstance(result, dict):
            results['decrypted_data'] = result
            results['decryption_method'] = f"{desc} with {method}"
            results['analysis'].append(f"Successfully decrypted using: {desc}")
            break
        elif isinstance(method, list):
            # method contains errors
            results['analysis'].append(f"Tried {desc}: failed")
    
    if not results['decrypted_data']:
        results['analysis'].append("Could not decrypt with known password patterns")
        results['analysis'].append("The salt may be stored in a separate location or derived differently")
    
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
  python3 decrypt_octo_storage.py --storage-dir "/home/vncuser/.Octo Browser"
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
    
    # Print encryption information from Ghidra analysis
    print("\n" + "="*70)
    print("ENCRYPTION DETAILS (from Ghidra Analysis)")
    print("="*70)
    print(f"""
  Algorithm: Fernet (AES-128-CBC + HMAC-SHA256)
  Key Derivation: PBKDF2-HMAC-SHA256
  
  Key Derivation Parameters (from octo_crypto/encryption/ciphers/fernet.pyc):
    - Algorithm: SHA256
    - Key Length: {PBKDF2_KEY_LENGTH} bytes
    - Iterations: {PBKDF2_ITERATIONS}
    - Salt Length: {PBKDF2_SALT_LENGTH} bytes
    
  Constants (from config.pyc):
    - SECRET_KEY: "{SECRET_KEY}"
    - APP_ID: "{OCTO_APP_ID}"
    
  Storage (from octo/helpers/storage.pyc):
    - Password/Passphrase: Machine HID directly
    - Files encrypted per-user with unique salt
    
  File Formats:
    - Legacy: Raw Fernet token (starts with gAAAAAB)
    - New: Header with version, cipher type, salt, metadata + ciphertext
""")
    
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
