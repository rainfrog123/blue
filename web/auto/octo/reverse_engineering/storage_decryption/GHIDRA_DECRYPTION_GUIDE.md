# Reverse Engineering OctoBrowser Storage Encryption with Ghidra

A step-by-step guide on how to manually discover encryption parameters for OctoBrowser's `local.data` and `localpersist.data` files using Ghidra.

## Prerequisites

- Ghidra installed (`/opt/ghidra`)
- OctoBrowser AppImage or installation
- Python 3.x with `cryptography` library
- Basic understanding of Python bytecode and encryption

## Overview

OctoBrowser encrypts its local storage files using:
- **Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Password**: Machine HID (Hardware ID)

The goal is to find the exact parameters needed to decrypt these files.

---

## Phase 1: Extract the Binary

### 1.1 Locate OctoBrowser

```bash
# Find the AppImage
find /home -name "OctoBrowser*.AppImage" 2>/dev/null

# Common locations:
# ~/Downloads/OctoBrowser.AppImage
# ~/.local/share/OctoBrowser.AppImage
```

### 1.2 Identify Binary Type

```bash
file /path/to/OctoBrowser.AppImage

# Output: ELF 64-bit LSB executable...
```

### 1.3 Check for PyInstaller

OctoBrowser is a PyInstaller-packed Python application:

```bash
# Search for PyInstaller markers
strings OctoBrowser.AppImage | grep -E "MEI|PYZ"

# If you see "MEI" and "PYZ", it's PyInstaller
```

### 1.4 Extract with PyInstxtractor

```bash
# Download pyinstxtractor
curl -sL https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -o pyinstxtractor.py

# Extract the binary
python3 pyinstxtractor.py OctoBrowser.AppImage

# Output directory: OctoBrowser.AppImage_extracted/
```

---

## Phase 2: Locate Encryption Files

### 2.1 Find Relevant .pyc Files

```bash
# List all extracted files
find OctoBrowser.AppImage_extracted -name "*.pyc" | head -50

# Key files to look for:
# - config.pyc                    (contains SECRET_KEY)
# - octo_crypto/encryption/*.pyc  (encryption logic)
# - octo/helpers/encryption.pyc   (key derivation)
# - octo/helpers/storage.pyc      (storage class)
```

### 2.2 Identify Target Files

The most important files are:

| File | Contents |
|------|----------|
| `PYZ.pyz_extracted/config.pyc` | SECRET_KEY, HID retrieval methods |
| `PYZ.pyz_extracted/octo_crypto/encryption/ciphers/fernet.pyc` | PBKDF2 iterations |
| `PYZ.pyz_extracted/octo/helpers/encryption.pyc` | password_hash() function |
| `PYZ.pyz_extracted/octo/helpers/storage.pyc` | Storage class, passphrase usage |

---

## Phase 3: Quick Analysis with Strings

Before using Ghidra, extract readable strings:

### 3.1 Find SECRET_KEY

```bash
strings PYZ.pyz_extracted/config.pyc | grep -i "secret\|key\|tentacle"

# Expected output:
# OCTO_SECRET_KEY
# TeNtAcLeShErE___
```

### 3.2 Find Encryption Method

```bash
strings PYZ.pyz_extracted/octo_crypto/encryption/ciphers/fernet.pyc

# Look for:
# - Fernet
# - PBKDF2HMAC
# - SHA256
# - iterations
# - salt
```

### 3.3 Find Storage Passphrase

```bash
strings PYZ.pyz_extracted/octo/helpers/storage.pyc | head -50

# Look for:
# - passphrase
# - hid
# - encrypt
# - decrypt
```

---

## Phase 4: Analyze with Python Marshal

Python bytecode contains constants we can extract directly:

### 4.1 Extract Constants from .pyc

```python
import marshal

def analyze_pyc(path):
    with open(path, 'rb') as f:
        # Skip header (16 bytes for Python 3.12)
        f.read(16)
        code = marshal.load(f)
    
    print(f"Code name: {code.co_name}")
    print(f"Constants: {code.co_consts[:20]}")
    
    # Find numeric constants (iterations)
    for const in code.co_consts:
        if isinstance(const, int) and const > 10000:
            print(f"Large integer found: {const}")
        
        # Check nested code objects
        if hasattr(const, 'co_consts'):
            for nested in const.co_consts:
                if isinstance(nested, int) and nested > 10000:
                    print(f"Nested large integer: {nested}")

# Analyze the fernet cipher
analyze_pyc('PYZ.pyz_extracted/octo_crypto/encryption/ciphers/fernet.pyc')

# Expected output:
# Nested large int: 100000  <-- This is PBKDF2 iterations!
```

---

## Phase 5: Ghidra Analysis (Deep Dive)

### 5.1 Launch Ghidra

```bash
# Start Ghidra GUI (requires display)
DISPLAY=:1 /opt/ghidra/ghidraRun

# Or headless mode
/opt/ghidra/support/analyzeHeadless /tmp/project OctoAnalysis \
    -import OctoBrowser.AppImage \
    -postScript analyze_script.py
```

### 5.2 Create Analysis Project

1. **File → New Project → Non-Shared Project**
2. Name: `OctoBrowser_Decrypt`
3. Location: `/tmp/ghidra_projects`

### 5.3 Import Binary

1. **File → Import File**
2. Select `OctoBrowser.AppImage`
3. Accept ELF format
4. Click **Analyze** when prompted

### 5.4 Search for Encryption Strings

1. **Search → For Strings** (or press `S`)
2. Search for:
   - `TeNtAcLeShErE`
   - `PBKDF2`
   - `Fernet`
   - `machine-id`
   - `iterations`

### 5.5 Find Cross-References

For each found string:
1. Double-click to navigate
2. Right-click → **References → Show References to Address**
3. Follow the call chain to understand usage

### 5.6 Create Headless Analysis Script

```python
# ghidra_encryption_analyzer.py
# Run with: analyzeHeadless ... -postScript ghidra_encryption_analyzer.py

from ghidra.program.model.listing import Function

SEARCH_STRINGS = [
    "TeNtAcLeShErE",
    "PBKDF2",
    "Fernet", 
    "iterations",
    "machine-id",
    "/etc/machine-id",
]

def find_strings():
    listing = currentProgram.getListing()
    dataIterator = listing.getDefinedData(True)
    
    while dataIterator.hasNext():
        data = dataIterator.next()
        if data.hasStringValue():
            value = str(data.getValue())
            for term in SEARCH_STRINGS:
                if term.lower() in value.lower():
                    print(f"[STRING] {value[:80]} @ {data.getAddress()}")

find_strings()
```

---

## Phase 6: Key Discovery Summary

After analysis, you should find:

### 6.1 Encryption Parameters

| Parameter | Value | Source File |
|-----------|-------|-------------|
| Algorithm | Fernet (AES-128-CBC) | `fernet.pyc` |
| KDF | PBKDF2-HMAC-SHA256 | `fernet.pyc` |
| Iterations | **100,000** | `fernet.pyc` (nested constant) |
| Key Length | 32 bytes | `fernet.pyc` |
| Salt Length | 16 bytes | `encryptor.pyc` |

### 6.2 Key Material

| Item | Value | Source |
|------|-------|--------|
| SECRET_KEY | `TeNtAcLeShErE___` | `config.pyc` |
| APP_ID | `octo-c6cfa04f-4432-ae38-15bdc035170f` | `config.pyc` |
| Password | Machine HID | `storage.pyc` |

### 6.3 HID Sources (by platform)

| Platform | Method | Command/File |
|----------|--------|--------------|
| Linux | File read | `/etc/machine-id` |
| macOS | Shell command | `ioreg -rd1 -c IOPlatformExpertDevice \| grep UUID` |
| Windows | PowerShell | `(Get-CimInstance Win32_ComputerSystemProduct).UUID` |

---

## Phase 7: Build the Decryption Function

With discovered parameters, implement decryption:

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Discovered parameters
ITERATIONS = 100000
KEY_LENGTH = 32
SALT_LENGTH = 16

def get_linux_hid():
    """Read machine ID from /etc/machine-id"""
    with open('/etc/machine-id', 'r') as f:
        return f.read().strip()

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive Fernet key using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_storage(filepath: str, hid: str) -> dict:
    """Decrypt OctoBrowser storage file"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Salt strategy: first 16 bytes of HID (padded)
    salt = hid.encode()[:SALT_LENGTH].ljust(SALT_LENGTH, b'\x00')
    
    key = derive_key(hid, salt)
    f = Fernet(key)
    decrypted = f.decrypt(data)
    
    return json.loads(decrypted)

# Usage
hid = get_linux_hid()
content = decrypt_storage('~/.Octo Browser/local.data', hid)
print(json.dumps(content, indent=2))
```

---

## Phase 8: Verification

### 8.1 Test Decryption

```bash
python3 octo_storage_decryptor.py --storage-dir ~/.Octo\ Browser/

# Expected output:
# Successfully decrypted using: HID only
# {
#     "uuid": "...",
#     "access_token": "...",
#     "email": "...",
#     ...
# }
```

### 8.2 Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| InvalidToken | Wrong salt | Try different salt strategies |
| Bad base64 | New file format | Check for version header |
| Empty result | Compression | Try `zlib.decompress()` |

---

## Files in This Directory

| File | Description |
|------|-------------|
| `octo_storage_decryptor.py` | Working decryption script |
| `ghidra_encryption_analyzer.py` | Ghidra encryption analysis script |
| `GHIDRA_DECRYPTION_GUIDE.md` | This guide |
| `local.data.decrypted.json` | Decrypted session storage sample |
| `localpersist.data.decrypted.json` | Decrypted persistent storage sample |

---

## Quick Reference: Decryption Formula

```
Password  = /etc/machine-id (Linux)
Salt      = Password[:16].ljust(16, '\x00')
Key       = PBKDF2(SHA256, Password, Salt, iterations=100000, length=32)
Fernet_Key = base64_urlsafe_encode(Key)
Plaintext = Fernet(Fernet_Key).decrypt(ciphertext)
Content   = json.loads(Plaintext)
```

---

## Security Notes

- The HID is sent to OctoBrowser servers during authentication
- Changing HID requires re-authentication
- Storage files are encrypted per-machine
- The SECRET_KEY adds no security (it's hardcoded and discoverable)
