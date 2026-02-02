# HID (Hardware ID) Fingerprinting Analysis

Analysis of how OctoBrowser collects and uses hardware fingerprints for machine identification.

## Summary

OctoBrowser collects a Hardware ID (HID) from the system to uniquely identify the machine. This HID is used for:

1. **Encryption Key**: Passphrase for PBKDF2 key derivation to encrypt local storage
2. **License Binding**: Sent to server for license validation  
3. **Client Identification**: Part of authentication state

## HID Collection Methods

| Platform | Method | Command/Path |
|----------|--------|--------------|
| **Linux** | machine-id | `/etc/machine-id` |
| **macOS** | ioreg | `ioreg -rd1 -c IOPlatformExpertDevice \| grep UUID` |
| **Windows** (primary) | PowerShell | `(Get-CimInstance Win32_ComputerSystemProduct).UUID` |
| **Windows** (fallback) | WMIC | `wmic csproduct get uuid` |

### Current Machine HID

```bash
# Linux
cat /etc/machine-id
# Output: af4c53bb49a540c397c79cbed8d57ab0
```

## Storage Locations

| File | Path | Purpose |
|------|------|---------|
| Session Storage | `~/.Octo Browser/local.data` | Temporary session data |
| Persistent Storage | `~/.Octo Browser/localpersist.data` | Auth tokens, user state |
| Language | `~/.Octo Browser/lang` | UI language |
| Local Port | `~/.Octo Browser/local_port` | Local API server port |

## Storage Encryption

```
Algorithm: Fernet (AES-128-CBC + HMAC-SHA256)
Key Derivation: PBKDF2-HMAC-SHA256

Parameters:
  - Password: Machine HID + SECRET_KEY
  - SECRET_KEY: "TeNtAcLeShErE___"
  - Iterations: ~100,000-480,000
  - Salt: Stored in encrypted file or fixed

File Format:
  gAAAAAB...  (Base64 encoded Fernet token)
```

## Ghidra Analysis Results

### libdbus-1.so.3 Functions

| Function | Offset | Purpose |
|----------|--------|---------|
| `_dbus_read_local_machine_uuid` | 0x136190 | Reads /etc/machine-id |
| `_dbus_get_local_machine_uuid_encoded` | 0x136390 | Returns encoded UUID |
| `dbus_get_local_machine_id` | (exported) | Public API |
| `_dbus_create_uuid` | 0x1271b0 | Creates UUID structure |
| `_dbus_generate_uuid` | 0x1350e0 | Generates new UUID |
| `_dbus_uuid_encode` | 0x1309a0 | Encodes to string |

### Python Code Structures

```python
@dataclass
class ClientStateData:
    cid: Optional[str] = None  # Client ID

@dataclass  
class AuthStateData:
    uuid: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    email: Optional[str] = None
    last_login_email: Optional[str] = None
```

## HID Spoofing

### Linux

```bash
# 1. Backup current machine-id
sudo cp /etc/machine-id /etc/machine-id.backup

# 2. Generate new machine-id

# Method A: Random via systemd
sudo rm /etc/machine-id
sudo systemd-machine-id-setup

# Method B: Set specific value (32 hex characters)
echo "00000000000000000000000000000001" | sudo tee /etc/machine-id

# Method C: Generate random manually
python3 -c "import uuid; print(uuid.uuid4().hex)" | sudo tee /etc/machine-id

# 3. Delete OctoBrowser storage (encrypted with old HID)
rm -f ~/.Octo\ Browser/local.data
rm -f ~/.Octo\ Browser/localpersist.data

# 4. Restart OctoBrowser - new storage will use new HID
```

### Windows

```powershell
# Windows UUID is from SMBIOS - cannot change without BIOS modification
# Alternative: Binary patch the PowerShell/WMI calls
```

### macOS

```bash
# IOPlatformUUID is hardware-based - cannot easily change
# Alternative: Binary patch the ioreg call
```

## Files

| File | Purpose |
|------|---------|
| `ghidra_hid_analyzer.py` | Main HID analysis and documentation |
| `ghidra_hid_analysis_script.py` | Ghidra headless script |
| `decrypt_octo_storage.py` | Attempt to decrypt storage files |

## Running Analysis

### Ghidra Headless

```bash
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects OctoHID \
  -import /tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3 \
  -postScript ghidra_hid_analysis_script.py
```

### Ghidra GUI

```bash
DISPLAY=:1 /opt/ghidra/ghidraRun
# Import libdbus-1.so.3
# Search > For Strings > "machine"
# Navigate to dbus_get_local_machine_id
```

### Storage Analysis

```bash
python3 decrypt_octo_storage.py --storage-dir "/home/vncuser/.Octo Browser"
```

## Python Bytecode Analysis

Key files to decompile (use pycdc or uncompyle6):

| File | Contents |
|------|----------|
| `config.pyc` | HID reading logic, secrets |
| `octo/helpers/storage.pyc` | Storage encryption |
| `octo/helpers/encryption.pyc` | Key derivation |
| `octo/client/state.pyc` | Client state model |

```bash
# Decompile with pycdc
pycdc /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/config.pyc
```

## Server Communication

The HID is sent to OctoBrowser servers during:

1. Initial authentication/login
2. License validation checks
3. Profile synchronization

### Endpoints

| Domain | Purpose |
|--------|---------|
| `app.octobrowser.net` | Main API |
| `app01.octobrowser.net` | Secondary API |
| `app.obiwankenode.com` | Internal API |

## Monitoring HID Access

```bash
# Trace file opens
strace -f -e openat <octobrowser> 2>&1 | grep -E '/etc/machine-id|/dev/|/sys/'

# Monitor in real-time
inotifywait -m /etc/machine-id

# Check open files
lsof -c octobrowser | grep machine-id
```

## Notes

- HID is 32 hexadecimal characters on Linux
- Changing HID invalidates encrypted storage
- Server may detect HID changes and require re-authentication
- HID + SECRET_KEY derive the encryption key
