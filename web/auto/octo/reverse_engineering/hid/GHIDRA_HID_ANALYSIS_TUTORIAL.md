# Reverse Engineering OctoBrowser HID with Ghidra

A step-by-step guide on how Ghidra was used to discover OctoBrowser's hardware fingerprinting mechanism.

## Prerequisites

- Ghidra installed (`/opt/ghidra`)
- OctoBrowser AppImage extracted
- Basic understanding of x86-64 assembly
- VNC or X11 display for GUI

## Phase 1: Extract the Target

### 1.1 Extract AppImage

AppImage files are self-extracting archives. Extract to analyze the contents:

```bash
# Make executable and extract
chmod +x OctoBrowser.AppImage
./OctoBrowser.AppImage --appimage-extract

# Or extract manually
cd /tmp
unsquashfs OctoBrowser.AppImage
mv squashfs-root OctoBrowser.AppImage_extracted
```

### 1.2 Identify Target Libraries

OctoBrowser is a PyInstaller-packaged Python application. Key files:

```bash
ls -la /tmp/OctoBrowser.AppImage_extracted/

# Interesting targets:
# - libdbus-1.so.3      # D-Bus library (reads machine-id)
# - PYZ.pyz             # Python bytecode archive
# - *.pyc               # Compiled Python files
```

**Why libdbus?** Linux applications commonly use D-Bus to get the machine ID. The `dbus_get_local_machine_id()` function reads `/etc/machine-id`.

## Phase 2: Initial Reconnaissance

### 2.1 String Search (Quick Win)

Before diving deep, search for obvious strings:

```bash
# Search for "machine" in all binaries
strings /tmp/OctoBrowser.AppImage_extracted/*.so* | grep -i machine

# Output reveals:
# machine-id
# /etc/machine-id
# dbus_get_local_machine_id
```

This immediately tells us the HID comes from `/etc/machine-id` via D-Bus.

### 2.2 Trace Runtime Behavior

Confirm with strace:

```bash
strace -f -e openat ./OctoBrowser.AppImage 2>&1 | grep machine-id

# Output:
# openat(AT_FDCWD, "/etc/machine-id", O_RDONLY) = 5
```

Now we know WHERE the HID comes from. Ghidra will show us HOW it's used.

## Phase 3: Ghidra Setup

### 3.1 Launch Ghidra

```bash
DISPLAY=:1 /opt/ghidra/ghidraRun
```

### 3.2 Create Project

1. **File → New Project**
2. Select "Non-Shared Project"
3. Name: `OctoBrowser_HID`
4. Location: `/tmp/ghidra_projects`

### 3.3 Import Binary

1. **File → Import File**
2. Navigate to `/tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3`
3. Accept default format (ELF)
4. Click "OK" and wait for import

### 3.4 Auto-Analysis

When prompted "Analyze now?", click **Yes** and enable:

- [x] ASCII Strings
- [x] Decompiler Parameter ID
- [x] Function Start Search
- [x] Reference Analysis
- [x] Stack Analysis

Wait for analysis to complete (watch bottom status bar).

## Phase 4: Finding HID Functions

### 4.1 Method 1: String Search

1. **Search → For Strings** (or press `S`)
2. Search for: `machine`
3. Results show references to "machine-id" and "/etc/machine-id"

Double-click a result to navigate to the string in memory.

### 4.2 Method 2: Symbol Search

1. **Search → For Address Tables**
2. Or use **Symbol Table** window (Window → Symbol Table)
3. Filter by: `machine`

Key symbols found:

| Symbol | Type | Purpose |
|--------|------|---------|
| `dbus_get_local_machine_id` | Export | Public API |
| `_dbus_read_local_machine_uuid` | Internal | Reads /etc/machine-id |
| `_dbus_get_local_machine_uuid_encoded` | Internal | Returns hex string |

### 4.3 Method 3: Cross-References (XREF)

1. Find the string `/etc/machine-id` in the Listing view
2. Right-click → **References → Show References to Address**
3. This shows all functions that reference this path

## Phase 5: Decompilation Analysis

### 5.1 Navigate to Function

Double-click `_dbus_read_local_machine_uuid` in Symbol Table.

### 5.2 View Decompiled Code

The **Decompile** window (right panel) shows C-like pseudocode:

```c
// Ghidra decompilation of _dbus_read_local_machine_uuid
// Address: 0x136190

int _dbus_read_local_machine_uuid(DBusGUID *machine_id, int create_if_missing, DBusError *error)
{
    int result;
    char *uuid_str;
    
    // Try to read from /etc/machine-id
    result = _dbus_read_uuid_file("/etc/machine-id", machine_id, 0, error);
    
    if (result == 0 && create_if_missing) {
        // Generate new UUID if file doesn't exist
        _dbus_generate_uuid(machine_id, error);
        _dbus_write_uuid_file("/etc/machine-id", machine_id, error);
    }
    
    return result;
}
```

### 5.3 Understand the Data Flow

Follow the call chain:

```
dbus_get_local_machine_id()          [Public API]
    ↓
_dbus_get_local_machine_uuid_encoded()
    ↓
_dbus_read_local_machine_uuid()      [Reads /etc/machine-id]
    ↓
_dbus_uuid_encode()                  [Converts to hex string]
```

### 5.4 Rename Variables

Ghidra's auto-generated names are cryptic. Improve readability:

1. Click on a variable (e.g., `param_1`)
2. Press `L` to rename
3. Give meaningful name (e.g., `machine_id_out`)

## Phase 6: Understanding the UUID Structure

### 6.1 Find Structure Definition

Search for `_dbus_create_uuid` and examine:

```c
// DBusGUID structure (16 bytes)
void _dbus_create_uuid(DBusGUID *uuid)
{
    // uuid->as_uint32s[0] = timestamp
    // uuid->as_uint32s[1] = random
    // uuid->as_uint32s[2] = random  
    // uuid->as_uint32s[3] = random
}
```

### 6.2 Define Custom Structure

1. **Data Type Manager** window
2. Right-click → **New → Structure**
3. Define:

```c
struct DBusGUID {
    uint32_t as_uint32s[4];  // 16 bytes total
};
```

4. Apply to function parameters for clearer decompilation

## Phase 7: Tracing Usage in Python

### 7.1 Extract Python Bytecode

```bash
cd /tmp/OctoBrowser.AppImage_extracted

# The PYZ.pyz is a ZIP archive of .pyc files
unzip -d PYZ.pyz_extracted PYZ.pyz
```

### 7.2 Find Relevant Modules

```bash
ls PYZ.pyz_extracted/ | grep -E 'config|storage|encrypt|state'

# Key files:
# config.pyc
# octo/helpers/storage.pyc
# octo/helpers/encryption.pyc
```

### 7.3 Decompile Python Bytecode

```bash
# Using pycdc (Python bytecode decompiler)
pycdc PYZ.pyz_extracted/config.pyc

# Or uncompyle6
uncompyle6 PYZ.pyz_extracted/config.pyc
```

Decompiled `config.pyc` reveals:

```python
import subprocess

def get_machine_id():
    """Get hardware ID for this machine"""
    # Linux
    try:
        with open('/etc/machine-id', 'r') as f:
            return f.read().strip()
    except:
        pass
    
    # macOS
    try:
        result = subprocess.run(
            ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
            capture_output=True, text=True
        )
        # Parse UUID from output
        ...
    except:
        pass
    
    # Windows
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             '(Get-CimInstance Win32_ComputerSystemProduct).UUID'],
            capture_output=True, text=True
        )
        return result.stdout.strip()
    except:
        pass

SECRET_KEY = "TeNtAcLeShErE___"
```

## Phase 8: Discovering Encryption

### 8.1 Analyze storage.pyc

Decompiled code shows:

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

def derive_key(machine_id: str, secret: str) -> bytes:
    """Derive Fernet key from machine ID"""
    password = (machine_id + secret).encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=b'octobrowser_salt',  # or stored in file
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_storage(data: dict, machine_id: str) -> str:
    key = derive_key(machine_id, SECRET_KEY)
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode()).decode()

def decrypt_storage(encrypted: str, machine_id: str) -> dict:
    key = derive_key(machine_id, SECRET_KEY)
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted.encode()))
```

### 8.2 Key Discovery Summary

| Component | Value/Method |
|-----------|--------------|
| Algorithm | Fernet (AES-128-CBC + HMAC-SHA256) |
| KDF | PBKDF2-HMAC-SHA256 |
| Password | `machine_id + "TeNtAcLeShErE___"` |
| Iterations | 100,000+ |
| Salt | Fixed or stored in file header |

## Phase 9: Headless Analysis (Automation)

### 9.1 Ghidra Headless Script

Create `ghidra_hid_analysis_script.py`:

```python
# Ghidra Python script for automated analysis
# Run with: analyzeHeadless

from ghidra.program.model.symbol import SymbolType

def find_machine_id_functions():
    """Find all functions related to machine-id"""
    results = []
    
    symbol_table = currentProgram.getSymbolTable()
    
    # Search for symbols containing "machine"
    for symbol in symbol_table.getAllSymbols(True):
        name = symbol.getName().lower()
        if 'machine' in name and 'uuid' in name:
            results.append({
                'name': symbol.getName(),
                'address': symbol.getAddress(),
                'type': symbol.getSymbolType()
            })
    
    return results

def analyze_function(func_addr):
    """Decompile and analyze a function"""
    from ghidra.app.decompiler import DecompInterface
    
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    func = getFunctionAt(func_addr)
    result = decomp.decompileFunction(func, 60, monitor)
    
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

# Main execution
print("=== OctoBrowser HID Analysis ===")
functions = find_machine_id_functions()

for func in functions:
    print(f"\nFunction: {func['name']}")
    print(f"Address: {func['address']}")
    
    code = analyze_function(func['address'])
    if code:
        print("Decompiled:")
        print(code[:500])  # First 500 chars
```

### 9.2 Run Headless

```bash
/opt/ghidra/support/analyzeHeadless \
    /tmp/ghidra_projects OctoHID \
    -import /tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3 \
    -postScript ghidra_hid_analysis_script.py \
    -scriptPath /allah/blue/web/auto/octo/hid \
    2>&1 | tee ghidra_analysis.log
```

## Phase 10: Key Findings Summary

### What Ghidra Revealed

1. **HID Source**: `/etc/machine-id` on Linux (via libdbus)
2. **Function Chain**: `dbus_get_local_machine_id` → `_dbus_read_local_machine_uuid`
3. **Format**: 32 hexadecimal characters (128-bit UUID)

### What Python Decompilation Revealed

1. **Cross-Platform Collection**: Different methods per OS
2. **Secret Key**: `"TeNtAcLeShErE___"` hardcoded
3. **Encryption**: Fernet with PBKDF2 key derivation
4. **Usage**: HID used for storage encryption AND server auth

### Attack Surface

```
/etc/machine-id → HID → PBKDF2(HID + SECRET) → Fernet Key → Encrypted Storage
                   ↓
              Server Auth (license binding)
```

## Ghidra Tips & Tricks

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename (label) |
| `T` | Set data type |
| `C` | Clear/Undefine |
| `D` | Disassemble |
| `F` | Create function |
| `;` | Add comment |
| `Ctrl+Shift+E` | Show references |

### Useful Windows

- **Decompile**: C pseudocode (most useful!)
- **Listing**: Assembly view
- **Symbol Table**: All named symbols
- **Function Graph**: Visual control flow
- **Defined Strings**: All strings in binary

### When Decompilation Fails

1. **Check function bounds**: Press `F` to redefine function
2. **Fix calling convention**: Right-click function → Edit Function
3. **Define structures**: Create proper data types
4. **Look at assembly**: Sometimes clearer than bad decompilation

## Conclusion

The complete HID discovery process:

1. **Recon**: `strings` + `strace` to find `/etc/machine-id`
2. **Static Analysis**: Ghidra on `libdbus-1.so.3` to understand the read mechanism
3. **Python Decompilation**: Extract `.pyc` files to find encryption logic
4. **Connect the Dots**: HID → Key Derivation → Storage Encryption

This combination of dynamic tracing, static binary analysis, and bytecode decompilation reveals the complete fingerprinting and encryption scheme.
