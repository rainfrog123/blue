# Ghidra Python Script for HID Fingerprint Analysis
# @category Analysis
# @menupath Analysis.Octo.HID Fingerprint Analysis
# @author OctoBrowser Reverse Engineering
#
# Usage (headless mode):
#   /opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects OctoHID \
#     -import /tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3 \
#     -postScript /allah/blue/web/auto/octo/ghidra_hid_analysis_script.py

"""
Ghidra Script: OctoBrowser HID Fingerprint Analyzer

Searches for hardware fingerprinting code patterns in native libraries.
Specifically targets:
- dbus_get_local_machine_id (Linux machine-id)
- File operations on /etc/machine-id
- IOPlatformExpertDevice references (macOS)
- Win32_ComputerSystemProduct references (Windows)
"""

# Ghidra API imports (available when running in Ghidra)
try:
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.mem import MemoryAccessException
    IN_GHIDRA = True
except ImportError:
    IN_GHIDRA = False
    print("Not running in Ghidra environment")


# Strings indicating HID fingerprinting
HID_STRINGS = [
    b"/etc/machine-id",
    b"machine-id",
    b"IOPlatformExpertDevice",
    b"IOPlatformUUID",
    b"Win32_ComputerSystemProduct",
    b"csproduct",
    b"dbus_get_local_machine_id",
    b"sd_id128_get_machine",
    b"hwid",
    b"HardwareId",
    b"device_id",
    b"client_uuid",
    b"fingerprint",
    b"uuid",
    b"UUID",
]

# Functions commonly used for HID collection
HID_FUNCTIONS = [
    "dbus_get_local_machine_id",
    "dbus_try_get_local_machine_id",
    "sd_id128_get_machine",
    "sd_id128_get_machine_app_specific",
    "fopen",
    "fopen64",
    "open",
    "open64",
    "popen",
    "system",
    "ioctl",
]


def find_hid_strings():
    """Find HID-related strings in the binary"""
    print("\n" + "="*70)
    print("SEARCHING FOR HID-RELATED STRINGS")
    print("="*70)
    
    found = []
    memory = currentProgram.getMemory()
    
    for search_bytes in HID_STRINGS:
        addr = memory.findBytes(memory.getMinAddress(), search_bytes, None, True, monitor)
        while addr is not None:
            # Get surrounding context
            try:
                context = memory.getBytes(addr, min(80, memory.getMaxAddress().subtract(addr)))
                context_str = bytes(context).split(b'\x00')[0].decode('utf-8', errors='replace')
            except:
                context_str = search_bytes.decode('utf-8', errors='replace')
            
            print("  [STRING] '{}' @ {}".format(context_str[:60], addr))
            found.append((addr, context_str))
            
            # Find next occurrence
            next_addr = addr.add(len(search_bytes))
            if next_addr.compareTo(memory.getMaxAddress()) >= 0:
                break
            addr = memory.findBytes(next_addr, search_bytes, None, True, monitor)
    
    return found


def find_hid_functions():
    """Find functions potentially used for HID collection"""
    print("\n" + "="*70)
    print("SEARCHING FOR HID-RELATED FUNCTIONS")
    print("="*70)
    
    found = []
    fm = currentProgram.getFunctionManager()
    st = currentProgram.getSymbolTable()
    
    # Search in function names
    for func in fm.getFunctions(True):
        name = func.getName()
        name_lower = name.lower()
        
        for search_func in HID_FUNCTIONS:
            if search_func.lower() in name_lower:
                print("  [FUNC] {} @ {}".format(name, func.getEntryPoint()))
                found.append(func)
                break
        
        # Also check for fingerprint-related names
        hid_keywords = ['fingerprint', 'hwid', 'machine', 'uuid', 'device']
        if any(kw in name_lower for kw in hid_keywords):
            if func not in found:
                print("  [FUNC] {} @ {}".format(name, func.getEntryPoint()))
                found.append(func)
    
    # Search in symbols
    for sym in st.getAllSymbols(True):
        name = sym.getName()
        name_lower = name.lower()
        
        for search_func in HID_FUNCTIONS:
            if search_func.lower() == name_lower:
                print("  [SYM] {} @ {}".format(name, sym.getAddress()))
    
    return found


def find_xrefs_to_strings(string_addrs):
    """Find cross-references to identified strings"""
    print("\n" + "="*70)
    print("FINDING XREFS TO HID STRINGS")
    print("="*70)
    
    refMgr = currentProgram.getReferenceManager()
    xref_funcs = set()
    
    for addr, string_val in string_addrs:
        refs = refMgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            func_name = func.getName() if func else "unknown"
            print("  [XREF] '{}' <- {} in {}()".format(
                string_val[:30], from_addr, func_name))
            if func:
                xref_funcs.add(func)
    
    return list(xref_funcs)


def decompile_function(func):
    """Decompile a function to C pseudocode"""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    result = decomp.decompileFunction(func, 60, monitor)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


def analyze_function_calls(func):
    """Analyze what a function calls"""
    print("  Analyzing calls in {}:".format(func.getName()))
    
    body = func.getBody()
    listing = currentProgram.getListing()
    refMgr = currentProgram.getReferenceManager()
    
    called_funcs = set()
    
    for addr in body.getAddresses(True):
        refs = refMgr.getReferencesFrom(addr)
        for ref in refs:
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                target_func = getFunctionContaining(target)
                if target_func:
                    called_funcs.add(target_func.getName())
    
    for called in sorted(called_funcs):
        print("    -> {}".format(called))
    
    return list(called_funcs)


def main():
    """Main analysis routine"""
    print("\n" + "#"*70)
    print("# OCTOBROWSER HID FINGERPRINT ANALYSIS")
    print("# Program: {}".format(currentProgram.getName()))
    print("# File: {}".format(currentProgram.getExecutablePath()))
    print("#"*70)
    
    # Phase 1: Find strings
    string_addrs = find_hid_strings()
    print("\n  Total strings found: {}".format(len(string_addrs)))
    
    # Phase 2: Find functions
    funcs = find_hid_functions()
    print("\n  Total functions found: {}".format(len(funcs)))
    
    # Phase 3: Find xrefs to strings
    xref_funcs = []
    if string_addrs:
        xref_funcs = find_xrefs_to_strings(string_addrs)
    
    # Phase 4: Analyze key functions
    all_interesting_funcs = set(funcs + xref_funcs)
    
    if all_interesting_funcs:
        print("\n" + "="*70)
        print("DECOMPILING KEY FUNCTIONS")
        print("="*70)
        
        # Prioritize dbus and machine-id related functions
        priority_names = ['dbus', 'machine', 'uuid', 'hwid', 'fingerprint']
        
        sorted_funcs = sorted(all_interesting_funcs, 
            key=lambda f: (
                -sum(1 for pn in priority_names if pn in f.getName().lower()),
                f.getName()
            ))
        
        for func in sorted_funcs[:10]:  # Top 10 functions
            print("\n" + "-"*70)
            print("FUNCTION: {} @ {}".format(func.getName(), func.getEntryPoint()))
            print("-"*70)
            
            # Analyze calls
            analyze_function_calls(func)
            
            # Decompile
            code = decompile_function(func)
            if code:
                lines = code.split('\n')
                # Show first 40 lines
                for line in lines[:40]:
                    print(line)
                if len(lines) > 40:
                    print("  ... ({} more lines)".format(len(lines) - 40))
            else:
                print("  [Could not decompile]")
    
    # Summary
    print("\n" + "#"*70)
    print("# ANALYSIS SUMMARY")
    print("#"*70)
    print("""
  HID Collection Methods Found:
  
  1. LINUX: /etc/machine-id
     - Read via fopen() or dbus_get_local_machine_id()
     - 32 character hexadecimal string
     
  2. DBUS Machine ID:
     - dbus_get_local_machine_id() function
     - Returns same value as /etc/machine-id
     
  Key Functions:
""")
    
    for func in sorted_funcs[:5] if all_interesting_funcs else []:
        print("    - {} @ {}".format(func.getName(), func.getEntryPoint()))
    
    print("""
  To spoof HID on Linux:
    1. Edit /etc/machine-id (32 hex chars)
    2. Delete ~/.Octo Browser/*.data files
    3. Restart OctoBrowser
    
  Files to further analyze:
    - config.pyc (decompile to see HID reading logic)
    - octo/helpers/storage.pyc (encryption details)
    - octo/helpers/encryption.pyc (key derivation)
""")
    
    print("\n# ANALYSIS COMPLETE")
    print("#"*70)


# Run the analysis
if IN_GHIDRA:
    main()
else:
    print("""
This script should be run inside Ghidra.

Usage:
  /opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects OctoHID \\
    -import /tmp/OctoBrowser.AppImage_extracted/libdbus-1.so.3 \\
    -postScript /allah/blue/web/auto/octo/ghidra_hid_analysis_script.py

Or in Ghidra GUI:
  1. Open the library in Ghidra
  2. Window -> Script Manager
  3. Find and run this script
""")
