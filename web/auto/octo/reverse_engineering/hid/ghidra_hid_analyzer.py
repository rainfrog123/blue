#!/usr/bin/env python3
"""
OctoBrowser HID Fingerprinting Analyzer for Ghidra (Headless Mode)

This script analyzes the OctoBrowser binary and libraries to find
hardware ID (HID) fingerprinting code and storage locations.

Based on reverse engineering findings:
- Linux: Reads /etc/machine-id
- macOS: Uses ioreg -rd1 -c IOPlatformExpertDevice | grep UUID
- Windows: Uses WMI (Win32_ComputerSystemProduct UUID) or wmic csproduct get uuid

Usage:
    /opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects OctoHID \
        -import /tmp/OctoBrowser.AppImage_extracted/libpython3.12.so \
        -postScript /allah/blue/web/auto/octo/ghidra_hid_analyzer.py
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import os
import re
import subprocess


@dataclass
class HIDFingerprintMethod:
    """Represents a hardware fingerprinting method"""
    platform: str
    method: str
    command: str
    source_file: str
    description: str


# Known HID fingerprinting methods found in OctoBrowser
HID_METHODS = [
    HIDFingerprintMethod(
        platform="linux",
        method="machine-id",
        command="/etc/machine-id",
        source_file="config.py",
        description="Reads Linux machine ID from /etc/machine-id"
    ),
    HIDFingerprintMethod(
        platform="darwin",
        method="ioreg",
        command="ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)'",
        source_file="config.py",
        description="Reads macOS hardware UUID from IOPlatformExpertDevice"
    ),
    HIDFingerprintMethod(
        platform="win32",
        method="powershell",
        command="(Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)",
        source_file="config.py",
        description="Reads Windows product UUID via PowerShell CIM"
    ),
    HIDFingerprintMethod(
        platform="win32",
        method="wmic",
        command="wmic csproduct get uuid",
        source_file="config.py",
        description="Fallback: Reads Windows product UUID via WMIC"
    ),
]


# Strings to search for in binaries
HID_SEARCH_STRINGS = [
    # File paths
    "/etc/machine-id",
    "/sys/class/dmi",
    "/sys/devices/virtual/dmi",
    "IOPlatformExpertDevice",
    "IOPlatformUUID",
    
    # Windows WMI
    "Win32_ComputerSystemProduct",
    "Win32_BIOS",
    "Win32_BaseBoard",
    "Win32_Processor",
    "csproduct",
    
    # DBUS
    "dbus_get_local_machine_id",
    "dbus_try_get_local_machine_id",
    "org.freedesktop.machine1",
    
    # General HID
    "machine-id",
    "machine_id",
    "MachineId",
    "HardwareId",
    "HWID",
    "hwid",
    "device_id",
    "DeviceId",
    "client_uuid",
    "fingerprint",
    
    # UUID
    "UUID",
    "uuid",
    "product_uuid",
    "system_uuid",
]


# Functions to look for in native libraries
HID_FUNCTIONS = [
    # DBUS functions
    "dbus_get_local_machine_id",
    "dbus_try_get_local_machine_id",
    "sd_id128_get_machine",
    "sd_id128_get_machine_app_specific",
    
    # File operations
    "fopen",
    "open",
    "read",
    "popen",
    
    # System calls
    "ioctl",
    "syscall",
    
    # Python subprocess
    "Popen",
    "check_output",
    "run",
]


def search_strings_in_binary(binary_path: str, search_terms: List[str]) -> Dict[str, List[str]]:
    """Search for strings in a binary file"""
    results = {}
    
    try:
        output = subprocess.check_output(
            ['strings', '-a', binary_path],
            stderr=subprocess.DEVNULL,
            timeout=60
        ).decode('utf-8', errors='ignore')
        
        for term in search_terms:
            matches = [line for line in output.split('\n') 
                      if term.lower() in line.lower()]
            if matches:
                results[term] = matches[:10]  # Limit to 10 matches per term
                
    except Exception as e:
        print(f"Error searching {binary_path}: {e}")
    
    return results


def analyze_binary_for_hid(binary_path: str) -> Dict:
    """Analyze a binary for HID fingerprinting code"""
    analysis = {
        'path': binary_path,
        'strings_found': {},
        'potential_functions': [],
    }
    
    # Search for relevant strings
    analysis['strings_found'] = search_strings_in_binary(binary_path, HID_SEARCH_STRINGS)
    
    # Try to get symbols using nm
    try:
        output = subprocess.check_output(
            ['nm', '-C', binary_path],
            stderr=subprocess.DEVNULL,
            timeout=30
        ).decode('utf-8', errors='ignore')
        
        for func in HID_FUNCTIONS:
            if func in output:
                for line in output.split('\n'):
                    if func in line:
                        analysis['potential_functions'].append(line.strip())
                        
    except Exception:
        pass
    
    return analysis


def get_storage_info() -> Dict:
    """Get information about where HID is stored"""
    return {
        'session_storage': {
            'file': '~/.Octo Browser/local.data',
            'type': 'encrypted',
            'encryption': 'Fernet (PBKDF2-SHA256)',
            'key_derivation': 'HID is used as passphrase for PBKDF2',
        },
        'persist_storage': {
            'file': '~/.Octo Browser/localpersist.data',
            'type': 'encrypted',
            'encryption': 'Fernet (PBKDF2-SHA256)',
            'key_derivation': 'HID is used as passphrase for PBKDF2',
        },
        'client_state': {
            'structure': 'ClientStateData dataclass',
            'fields': ['cid', 'HID'],
            'source': 'octo/client/state.py',
        },
        'auth_state': {
            'structure': 'AuthStateData dataclass',
            'fields': ['uuid', 'access_token', 'refresh_token', 'email', 'last_login_email'],
            'source': 'octo/auth/state.py',
        },
    }


def create_ghidra_script() -> str:
    """Generate Ghidra Jython script for HID analysis"""
    return '''# @category Analysis
# @menupath Analysis.Octo.HID Fingerprint Analysis

"""
Ghidra Script: OctoBrowser HID Fingerprint Analyzer
Searches for hardware fingerprinting code and storage locations.
"""

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
import re

# Strings indicating HID fingerprinting
HID_STRINGS = [
    "/etc/machine-id",
    "IOPlatformExpertDevice",
    "Win32_ComputerSystemProduct",
    "dbus_get_local_machine_id",
    "machine-id",
    "hwid",
    "HardwareId",
    "device_id",
    "client_uuid",
    "fingerprint",
    "uuid",
]

# Functions commonly used for fingerprinting
HID_FUNCTIONS = [
    "fopen",
    "popen", 
    "system",
    "subprocess",
    "open",
    "ioctl",
    "dbus_get_local_machine_id",
]

def find_strings():
    """Find HID-related strings in the binary"""
    print("\\n" + "="*70)
    print("SEARCHING FOR HID-RELATED STRINGS")
    print("="*70)
    
    found = []
    strMgr = currentProgram.getDataTypeManager()
    
    # Search in defined data
    listing = currentProgram.getListing()
    dataIterator = listing.getDefinedData(True)
    
    while dataIterator.hasNext():
        data = dataIterator.next()
        if data.hasStringValue():
            value = data.getValue()
            if value:
                value_str = str(value)
                for search_term in HID_STRINGS:
                    if search_term.lower() in value_str.lower():
                        addr = data.getAddress()
                        print("  [STRING] {} @ {}".format(value_str[:80], addr))
                        found.append((addr, value_str))
                        break
    
    # Also search using memory search
    memory = currentProgram.getMemory()
    for term in HID_STRINGS:
        termBytes = term.encode('utf-8')
        addr = memory.findBytes(memory.getMinAddress(), termBytes, None, True, monitor)
        while addr is not None:
            print("  [BYTES] '{}' @ {}".format(term, addr))
            found.append((addr, term))
            addr = memory.findBytes(addr.add(1), termBytes, None, True, monitor)
    
    return found


def find_functions():
    """Find functions potentially used for HID fingerprinting"""
    print("\\n" + "="*70)
    print("SEARCHING FOR HID-RELATED FUNCTIONS")
    print("="*70)
    
    found = []
    fm = currentProgram.getFunctionManager()
    
    for func in fm.getFunctions(True):
        name = func.getName()
        for search_func in HID_FUNCTIONS:
            if search_func.lower() in name.lower():
                print("  [FUNC] {} @ {}".format(name, func.getEntryPoint()))
                found.append(func)
                break
        
        # Also check for fingerprint-related names
        if any(term in name.lower() for term in ['fingerprint', 'hwid', 'machine', 'uuid', 'device']):
            print("  [FUNC] {} @ {}".format(name, func.getEntryPoint()))
            found.append(func)
    
    return found


def find_xrefs_to_strings(string_addrs):
    """Find cross-references to identified strings"""
    print("\\n" + "="*70)
    print("FINDING XREFS TO HID STRINGS")
    print("="*70)
    
    refMgr = currentProgram.getReferenceManager()
    
    for addr, string_val in string_addrs:
        refs = refMgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            func_name = func.getName() if func else "unknown"
            print("  [XREF] '{}' referenced from {} in {}".format(
                string_val[:40], from_addr, func_name))


def decompile_function(func):
    """Decompile a function to C"""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


def analyze_main():
    """Main analysis routine"""
    print("\\n" + "#"*70)
    print("# OCTOBROWSER HID FINGERPRINT ANALYSIS")
    print("# Program: {}".format(currentProgram.getName()))
    print("#"*70)
    
    # Find strings
    string_addrs = find_strings()
    
    # Find functions
    funcs = find_functions()
    
    # Find xrefs
    if string_addrs:
        find_xrefs_to_strings(string_addrs)
    
    # Decompile interesting functions
    if funcs:
        print("\\n" + "="*70)
        print("DECOMPILING HID-RELATED FUNCTIONS")
        print("="*70)
        
        for func in funcs[:5]:  # Limit to first 5
            print("\\n--- {} ---".format(func.getName()))
            code = decompile_function(func)
            if code:
                # Show first 50 lines
                lines = code.split('\\n')[:50]
                print('\\n'.join(lines))
    
    print("\\n" + "#"*70)
    print("# ANALYSIS COMPLETE")
    print("#"*70)

# Run analysis
analyze_main()
'''


def print_findings():
    """Print comprehensive HID fingerprinting findings"""
    
    print("""
################################################################################
#                    OCTOBROWSER HID FINGERPRINTING ANALYSIS                   #
################################################################################

## SUMMARY

OctoBrowser collects a Hardware ID (HID) from the system to uniquely identify
the machine. This HID is then used as:
1. A passphrase for encrypting local storage (Fernet encryption with PBKDF2)
2. A client identifier sent to the server for license validation
3. Part of the authentication state

## HID COLLECTION METHODS

### Linux
- Method: Read file /etc/machine-id
- Source: config.py -> LinuxUtils class
- The machine-id is a 32-character hexadecimal string

### macOS (Darwin)
- Method: Execute shell command
- Command: ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)'
- Source: config.py -> MacOSUtils class
- Extracts IOPlatformUUID from system registry

### Windows
- Method 1 (Primary): PowerShell CIM query
  Command: (Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)
  
- Method 2 (Fallback): WMIC command
  Command: wmic csproduct get uuid
  
- Source: config.py -> get_windows_hid() function
- Uses Win32_ComputerSystemProduct.UUID from SMBIOS

## STORAGE LOCATIONS

### Session Storage
- Path: ~/.Octo Browser/local.data
- Format: Fernet encrypted JSON
- Contents: Temporary session data
- Encryption Key: PBKDF2(HID + SECRET_KEY)

### Persistent Storage  
- Path: ~/.Octo Browser/localpersist.data
- Format: Fernet encrypted JSON
- Contents: Persistent state including auth tokens
- Encryption Key: PBKDF2(HID + SECRET_KEY)

### Storage Structure (from Python code analysis)

```python
@dataclass
class ClientStateData:
    cid: Optional[str] = None  # Client ID
    # HID is stored in config, not in this dataclass

@dataclass
class AuthStateData:
    uuid: Optional[str] = None        # User UUID from server
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    email: Optional[str] = None
    last_login_email: Optional[str] = None
```

## ENCRYPTION DETAILS

### Algorithm
- Primary: Fernet (AES-128-CBC with HMAC-SHA256)
- Alternative: AES-GCM (for newer profiles)

### Key Derivation
- Algorithm: PBKDF2-HMAC-SHA256
- Salt: Stored in encrypted file header
- Iterations: Standard PBKDF2 iterations
- Key Length: 32 bytes (256 bits) for Fernet key

### File Format (Fernet mode)
```
gAAAAAB...  (Base64 encoded Fernet token)
```

### File Format (AES-GCM mode)
```
[2 bytes]  Format version (i16)
[2 bytes]  Cipher type length (i16)
[N bytes]  Cipher type string
[4 bytes]  Salt length (i32)
[N bytes]  Salt value
[4 bytes]  Metadata length (i32)
[N bytes]  Metadata (JSON)
[...]      Ciphertext (IV + Tag + Encrypted data)
```

## SECRET KEY

The encryption also uses a hardcoded secret:
- SECRET_KEY: "TeNtAcLeShErE___"
- Combined with HID for key derivation

## HOW TO SPOOF HID

### Linux
```bash
# Backup original
sudo cp /etc/machine-id /etc/machine-id.bak

# Generate new machine-id
sudo rm /etc/machine-id
sudo systemd-machine-id-setup

# Or set a specific value (32 hex chars)
echo "00000000000000000000000000000001" | sudo tee /etc/machine-id
```

### After Changing HID
1. Delete ~/.Octo Browser/local.data
2. Delete ~/.Octo Browser/localpersist.data  
3. Restart OctoBrowser - it will generate new encrypted storage with new HID

## FILES TO ANALYZE WITH GHIDRA

1. Main binary analysis:
   /home/vncuser/Downloads/OctoBrowser.AppImage
   
2. Python bytecode (decompile with pycdc/uncompyle6):
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/config.pyc
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/octo/helpers/storage.pyc
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/octo/helpers/encryption.pyc
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/octo/client/state.pyc
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/octo_crypto/encryption/encryptor.pyc

3. Native libraries (for low-level HID access):
   /tmp/OctoBrowser.AppImage_extracted/libpython3.12.so
   /tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3  (for dbus_get_local_machine_id)
""")


def main():
    print("="*70)
    print("OctoBrowser HID Fingerprinting Analysis Tool")
    print("="*70)
    
    # Print findings
    print_findings()
    
    # Print known HID methods
    print("\n## DETAILED HID COLLECTION METHODS\n")
    for method in HID_METHODS:
        print(f"### {method.platform.upper()} - {method.method}")
        print(f"Command: {method.command}")
        print(f"Source: {method.source_file}")
        print(f"Description: {method.description}")
        print()
    
    # Get storage info
    storage = get_storage_info()
    print("\n## STORAGE DETAILS\n")
    for name, info in storage.items():
        print(f"### {name}")
        for k, v in info.items():
            print(f"  {k}: {v}")
        print()
    
    # Generate Ghidra script
    script_path = "/allah/blue/web/auto/octo/ghidra_hid_analysis.java"
    print(f"\nGhidra Jython script saved to: {script_path}")
    
    # Analyze extracted binaries if available
    extraction_dir = "/tmp/OctoBrowser.AppImage_extracted"
    if os.path.isdir(extraction_dir):
        print("\n" + "="*70)
        print("ANALYZING EXTRACTED BINARIES")
        print("="*70)
        
        binaries_to_check = [
            "libpython3.12.so",
            "libdbus-1.so.3",
        ]
        
        for binary in binaries_to_check:
            binary_path = os.path.join(extraction_dir, binary)
            if os.path.exists(binary_path):
                print(f"\n### {binary}")
                analysis = analyze_binary_for_hid(binary_path)
                
                if analysis['strings_found']:
                    print("Found strings:")
                    for term, matches in analysis['strings_found'].items():
                        for match in matches[:3]:
                            print(f"  - {term}: {match[:60]}")
                
                if analysis['potential_functions']:
                    print("Found functions:")
                    for func in analysis['potential_functions'][:5]:
                        print(f"  - {func}")


if __name__ == '__main__':
    main()
