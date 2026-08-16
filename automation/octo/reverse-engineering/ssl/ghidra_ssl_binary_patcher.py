#!/usr/bin/env python3
"""
OctoBrowser SSL Pinning Bypass Patcher
Uses Ghidra analysis results to patch NSS certificate verification functions.

Discovered function offsets (from Ghidra/nm analysis):
- CERT_VerifyCertificate @ 0x2e960
- CERT_VerifyCertificateNow @ 0x2ef60
- CERT_VerifyCert @ 0x2d360
- CERT_VerifyCertNow @ 0x2d380
- CERT_PKIXVerifyCert @ 0x2abc0
- CERT_VerifyCertName @ 0x70e80
- CERT_VerifyOCSPResponseSignature @ 0x25900
- CERT_VerifyCACertForUsage @ 0x2c900

All functions return SECStatus where:
- SECSuccess = 0
- SECFailure = -1

Patch strategy: Replace function start with:
  endbr64           (f3 0f 1e fa) - keep for CFI
  xor eax, eax      (31 c0)       - return 0 (success)
  ret               (c3)          - return immediately
"""

import shutil
import sys
import os

# NSS Certificate Verification Functions to patch
NSS_FUNCTIONS = {
    # Function name: (offset, description, critical)
    'CERT_VerifyCertificate':        (0x2e960, 'Main certificate verification', True),
    'CERT_VerifyCertificateNow':     (0x2ef60, 'Immediate verification', True),
    'CERT_VerifyCert':               (0x2d360, 'Legacy verification wrapper', True),
    'CERT_VerifyCertNow':            (0x2d380, 'Legacy immediate verification', True),
    'CERT_PKIXVerifyCert':           (0x2abc0, 'PKIX path validation', True),
    'CERT_VerifyCertName':           (0x70e80, 'Hostname verification', True),
    'CERT_VerifyOCSPResponseSignature': (0x25900, 'OCSP response verification', False),
    'CERT_VerifyCACertForUsage':     (0x2c900, 'CA certificate verification', False),
}

# Patch bytes: endbr64 + xor eax,eax + ret + nops for alignment
PATCH_BYTES_SUCCESS = bytes([
    0xf3, 0x0f, 0x1e, 0xfa,  # endbr64 (Intel CET)
    0x31, 0xc0,               # xor eax, eax (return 0 = SECSuccess)
    0xc3,                     # ret
    0x90,                     # nop (padding)
])

# OpenSSL functions (for libssl.so.3)
OPENSSL_FUNCTIONS = {
    'SSL_get_verify_result': (0x34844, 'SSL verification result', True),
}

# OpenSSL patch: return 1 (X509_V_OK = 0, but some functions return 1 for success)
PATCH_BYTES_OPENSSL = bytes([
    0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
    0x31, 0xc0,               # xor eax, eax (return 0 = X509_V_OK)
    0xc3,                     # ret
    0x90,                     # nop
])

# For X509_verify_cert in libcrypto
PATCH_BYTES_RETURN_ONE = bytes([
    0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
    0xb8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
    0xc3,                     # ret
])


def verify_function_start(data: bytes, offset: int, func_name: str) -> bool:
    """Verify the function starts with expected bytes (endbr64)"""
    if offset + 4 > len(data):
        print(f"  [!] {func_name}: Offset 0x{offset:x} beyond file size")
        return False
    
    # Check for endbr64 instruction
    expected_endbr64 = bytes([0xf3, 0x0f, 0x1e, 0xfa])
    actual = data[offset:offset+4]
    
    if actual == expected_endbr64:
        return True
    
    # Some functions might not have endbr64 (older compilers)
    # Check for common function prologues
    common_prologues = [
        bytes([0x55]),                    # push rbp
        bytes([0x41, 0x57]),              # push r15
        bytes([0x48, 0x83]),              # sub rsp, ...
        bytes([0x48, 0x89]),              # mov ..., ...
    ]
    
    for prologue in common_prologues:
        if data[offset:offset+len(prologue)] == prologue:
            print(f"  [*] {func_name}: Found alternative prologue, patching anyway")
            return True
    
    print(f"  [!] {func_name}: Unexpected bytes at 0x{offset:x}: {actual.hex()}")
    return False


def patch_nss_library(input_path: str, output_path: str, critical_only: bool = False) -> bool:
    """Patch libnss3.so to bypass certificate verification"""
    
    print(f"\n{'='*70}")
    print(f"Patching NSS Library: {input_path}")
    print(f"{'='*70}\n")
    
    # Read the library
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    print(f"File size: {original_size} bytes (0x{original_size:x})\n")
    
    patched_count = 0
    
    for func_name, (offset, description, is_critical) in NSS_FUNCTIONS.items():
        if critical_only and not is_critical:
            print(f"  [SKIP] {func_name} (non-critical)")
            continue
            
        print(f"  Patching {func_name} @ 0x{offset:x}")
        print(f"          ({description})")
        
        if not verify_function_start(bytes(data), offset, func_name):
            print(f"  [WARN] Skipping {func_name} - verification failed\n")
            continue
        
        # Show original bytes
        original = data[offset:offset+8]
        print(f"          Original: {original.hex()}")
        
        # Apply patch
        patch = PATCH_BYTES_SUCCESS
        data[offset:offset+len(patch)] = patch
        
        print(f"          Patched:  {patch.hex()}")
        print()
        patched_count += 1
    
    # Write patched library
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"{'='*70}")
    print(f"Patched {patched_count} functions")
    print(f"Output: {output_path}")
    print(f"{'='*70}\n")
    
    return patched_count > 0


def patch_openssl_library(input_path: str, output_path: str) -> bool:
    """Patch libssl.so.3 to bypass SSL verification"""
    
    print(f"\n{'='*70}")
    print(f"Patching OpenSSL Library: {input_path}")
    print(f"{'='*70}\n")
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Find SSL_get_verify_result by searching for its symbol
    # This function should return X509_V_OK (0) for success
    
    # Try known offset first
    offset = 0x34844
    
    if offset + 8 <= len(data):
        original = data[offset:offset+8]
        print(f"  SSL_get_verify_result @ 0x{offset:x}")
        print(f"          Original: {original.hex()}")
        
        # Check if it looks like code
        if original[0:4] == bytes([0xf3, 0x0f, 0x1e, 0xfa]):  # endbr64
            patch = PATCH_BYTES_OPENSSL
            data[offset:offset+len(patch)] = patch
            print(f"          Patched:  {patch.hex()}")
        else:
            print(f"  [WARN] Unexpected bytes, trying alternative search...")
            # Search for the function
            return False
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"\nOutput: {output_path}\n")
    return True


def patch_crypto_library(input_path: str, output_path: str) -> bool:
    """Patch libcrypto.so.3 for X509_verify_cert"""
    
    print(f"\n{'='*70}")
    print(f"Patching Crypto Library: {input_path}")
    print(f"{'='*70}\n")
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    # X509_verify_cert returns 1 on success, 0 on failure
    # We need to find it and patch to return 1
    
    # Try to find by searching for symbol table
    # For now, skip this as NSS is the primary target
    
    shutil.copy(input_path, output_path)
    print("  [INFO] Crypto library copied without modification")
    print("         (NSS patches should be sufficient)\n")
    
    return True


def create_patched_extraction(extraction_dir: str, output_dir: str):
    """Create a complete patched extraction directory"""
    
    print(f"\n{'#'*70}")
    print("# OctoBrowser SSL Pinning Bypass - Complete Patcher")
    print(f"{'#'*70}\n")
    
    # Define paths
    nss_src = os.path.join(extraction_dir, 'libnss3.so')
    ssl_src = os.path.join(extraction_dir, 'libssl.so.3')
    crypto_src = os.path.join(extraction_dir, 'libcrypto.so.3')
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    nss_dst = os.path.join(output_dir, 'libnss3.so')
    ssl_dst = os.path.join(output_dir, 'libssl.so.3')
    crypto_dst = os.path.join(output_dir, 'libcrypto.so.3')
    
    success = True
    
    # Patch NSS (most important)
    if os.path.exists(nss_src):
        if not patch_nss_library(nss_src, nss_dst):
            print("[ERROR] Failed to patch libnss3.so")
            success = False
    else:
        print(f"[ERROR] libnss3.so not found at {nss_src}")
        success = False
    
    # Patch OpenSSL (backup)
    if os.path.exists(ssl_src):
        patch_openssl_library(ssl_src, ssl_dst)
    
    # Copy crypto (usually not needed)
    if os.path.exists(crypto_src):
        patch_crypto_library(crypto_src, crypto_dst)
    
    return success


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <extraction_dir> [output_dir]")
        print(f"       {sys.argv[0]} <libnss3.so> <output.so>")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} /tmp/OctoBrowser.AppImage_extracted /tmp/patched_libs")
        print(f"  {sys.argv[0]} libnss3.so libnss3.so.patched")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    if os.path.isdir(input_path):
        # Full extraction directory mode
        output_dir = sys.argv[2] if len(sys.argv) > 2 else '/tmp/octo_patched_libs'
        success = create_patched_extraction(input_path, output_dir)
        
        if success:
            print("\n" + "="*70)
            print("SUCCESS! Patched libraries created.")
            print("="*70)
            print(f"\nTo use the patched libraries:")
            print(f"  export LD_PRELOAD={output_dir}/libnss3.so")
            print(f"  # OR copy to extraction directory and run from there")
    else:
        # Single file mode
        output_path = sys.argv[2] if len(sys.argv) > 2 else input_path + '.patched'
        
        if 'nss' in input_path.lower():
            patch_nss_library(input_path, output_path)
        elif 'ssl' in input_path.lower():
            patch_openssl_library(input_path, output_path)
        else:
            print(f"Unknown library type: {input_path}")
            sys.exit(1)


if __name__ == '__main__':
    main()
