# @category Analysis
# @menupath Analysis.Octo.Decrypt Storage Analyzer
"""
Ghidra Headless Script: Find OctoBrowser encryption parameters

Searches for:
- Fernet encryption patterns
- PBKDF2 key derivation parameters
- SECRET_KEY and salt values
- Storage encryption functions
"""

from __future__ import print_function
import sys

# Ghidra imports (available in Ghidra's Jython environment)
try:
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface
    GHIDRA_ENV = True
except ImportError:
    GHIDRA_ENV = False
    print("Not running in Ghidra environment - standalone mode")


# Search patterns for encryption
ENCRYPTION_STRINGS = [
    # Fernet/Cryptography
    "Fernet",
    "fernet",
    "PBKDF2",
    "pbkdf2",
    "AES",
    "aes",
    "SHA256",
    "sha256",
    "HMAC",
    "hmac",
    
    # OctoBrowser specific
    "TeNtAcLeShErE",
    "tentacleshere",
    "SECRET_KEY",
    "secret_key",
    "octo-c6cfa04f",
    
    # Storage
    "local.data",
    "localpersist.data",
    "storage",
    "encrypt",
    "decrypt",
    
    # Key derivation
    "salt",
    "iterations",
    "derive_key",
    "password_hash",
    
    # Machine ID
    "machine-id",
    "machine_id",
    "/etc/machine-id",
    "HID",
    "hwid",
]

ENCRYPTION_FUNCTIONS = [
    "encrypt",
    "decrypt",
    "derive",
    "hash",
    "fernet",
    "pbkdf2",
    "storage",
    "password",
]


def find_encryption_strings():
    """Find encryption-related strings in binary"""
    print("\n" + "=" * 70)
    print("SEARCHING FOR ENCRYPTION STRINGS")
    print("=" * 70)
    
    found = []
    
    if not GHIDRA_ENV:
        return found
    
    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()
    
    # Search defined strings
    dataIterator = listing.getDefinedData(True)
    while dataIterator.hasNext():
        data = dataIterator.next()
        if data.hasStringValue():
            value = data.getValue()
            if value:
                value_str = str(value)
                for term in ENCRYPTION_STRINGS:
                    if term.lower() in value_str.lower():
                        addr = data.getAddress()
                        print("  [STRING] {} @ {}".format(value_str[:100], addr))
                        found.append((addr, value_str, term))
                        break
    
    # Also search raw bytes
    for term in ENCRYPTION_STRINGS:
        try:
            term_bytes = term.encode('utf-8')
            addr = memory.findBytes(memory.getMinAddress(), term_bytes, None, True, monitor)
            while addr is not None:
                # Avoid duplicates
                if not any(a == addr for a, _, _ in found):
                    print("  [BYTES] '{}' @ {}".format(term, addr))
                    found.append((addr, term, term))
                addr = memory.findBytes(addr.add(1), term_bytes, None, True, monitor)
        except Exception as e:
            pass
    
    return found


def find_encryption_functions():
    """Find functions related to encryption"""
    print("\n" + "=" * 70)
    print("SEARCHING FOR ENCRYPTION FUNCTIONS")
    print("=" * 70)
    
    found = []
    
    if not GHIDRA_ENV:
        return found
    
    fm = currentProgram.getFunctionManager()
    
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        for term in ENCRYPTION_FUNCTIONS:
            if term in name:
                print("  [FUNC] {} @ {}".format(func.getName(), func.getEntryPoint()))
                found.append(func)
                break
    
    return found


def find_xrefs(string_results):
    """Find cross-references to encryption strings"""
    print("\n" + "=" * 70)
    print("FINDING XREFS TO ENCRYPTION STRINGS")
    print("=" * 70)
    
    if not GHIDRA_ENV:
        return
    
    refMgr = currentProgram.getReferenceManager()
    
    for addr, value, term in string_results:
        refs = refMgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            func_name = func.getName() if func else "unknown"
            print("  [XREF] '{}' referenced from {} in function {}".format(
                term, from_addr, func_name))


def decompile_function(func):
    """Decompile a function to C pseudocode"""
    if not GHIDRA_ENV:
        return None
    
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    result = decomp.decompileFunction(func, 60, monitor)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


def analyze_encryption():
    """Main analysis routine"""
    print("\n" + "#" * 70)
    print("# OCTOBROWSER ENCRYPTION ANALYZER")
    if GHIDRA_ENV:
        print("# Program: {}".format(currentProgram.getName()))
    print("#" * 70)
    
    # Find strings
    string_results = find_encryption_strings()
    
    # Find functions
    func_results = find_encryption_functions()
    
    # Find xrefs
    if string_results:
        find_xrefs(string_results)
    
    # Decompile encryption functions
    if func_results:
        print("\n" + "=" * 70)
        print("DECOMPILING ENCRYPTION FUNCTIONS")
        print("=" * 70)
        
        for func in func_results[:10]:
            print("\n--- {} @ {} ---".format(func.getName(), func.getEntryPoint()))
            code = decompile_function(func)
            if code:
                lines = code.split('\n')[:80]
                print('\n'.join(lines))
    
    # Summary
    print("\n" + "#" * 70)
    print("# ANALYSIS SUMMARY")
    print("#" * 70)
    print("  Encryption strings found: {}".format(len(string_results)))
    print("  Encryption functions found: {}".format(len(func_results)))
    
    # Print key findings
    print("\n" + "=" * 70)
    print("KEY FINDINGS FOR DECRYPTION")
    print("=" * 70)
    print("""
Based on reverse engineering, OctoBrowser uses:

1. ENCRYPTION: Fernet (AES-128-CBC + HMAC-SHA256)
   
2. KEY DERIVATION: PBKDF2-HMAC-SHA256
   - Password: machine_id (from /etc/machine-id)
   - Salt: Stored in first bytes of encrypted file OR fixed
   - Iterations: 100000 or 480000 (standard cryptography defaults)
   
3. SECRET_KEY: "TeNtAcLeShErE___" (may be combined with HID)

4. STORAGE FILES:
   - ~/.Octo Browser/local.data (session data)
   - ~/.Octo Browser/localpersist.data (persistent auth)

5. FILE FORMAT:
   - Fernet tokens start with 'gAAAAAB'
   - Base64 URL-safe encoded
""")


# Run when executed in Ghidra
if GHIDRA_ENV:
    analyze_encryption()
elif __name__ == '__main__':
    print("Run this script in Ghidra headless mode:")
    print("/opt/ghidra/support/analyzeHeadless /tmp/ghidra_project OctoAnalysis \\")
    print("    -import /tmp/OctoBrowser_extracted/OctoBrowser.AppImage \\")
    print("    -postScript ghidra_decrypt_analyzer.py")
