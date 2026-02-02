#!/usr/bin/env python3
"""
OctoBrowser Complete SSL Pinning Bypass
Patches ALL SSL verification functions across all libraries.

Based on Ghidra analysis of:
- libcrypto.so.3 (OpenSSL)
- libssl.so.3 (OpenSSL)  
- libnss3.so (NSS)
- libQt6Network.so.6 (Qt)

All functions are patched to return success values.
"""

import os
import sys
import shutil
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class PatchTarget:
    name: str
    offset: int
    return_value: int  # 0 for success in NSS, 1 for success in OpenSSL cert verify
    description: str

# Patch bytes templates
def make_return_patch(return_value: int) -> bytes:
    """Create patch that returns specified value"""
    if return_value == 0:
        # endbr64; xor eax, eax; ret; nop
        return bytes([0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3, 0x90])
    elif return_value == 1:
        # endbr64; mov eax, 1; ret; nop nop
        return bytes([0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90])
    else:
        raise ValueError(f"Unsupported return value: {return_value}")

def make_noop_patch() -> bytes:
    """Create patch that does nothing (just returns)"""
    # endbr64; ret; nop nop nop
    return bytes([0xf3, 0x0f, 0x1e, 0xfa, 0xc3, 0x90, 0x90, 0x90])

# ============================================================================
# LIBCRYPTO.SO.3 - OpenSSL Crypto Library
# ============================================================================
LIBCRYPTO_PATCHES = [
    PatchTarget("X509_verify_cert", 0x2396e0, 1, "Main X509 cert chain verification"),
    PatchTarget("X509_verify", 0x237760, 1, "Certificate signature verification"),
    PatchTarget("X509_STORE_CTX_verify", 0x239b50, 1, "Store context verification"),
]

# ============================================================================
# LIBSSL.SO.3 - OpenSSL SSL Library
# ============================================================================
LIBSSL_PATCHES = [
    PatchTarget("SSL_get_verify_result", 0x34840, 0, "Returns X509_V_OK (0) = success"),
    PatchTarget("SSL_CTX_set_verify", 0x34130, -1, "Disable verify callback (noop)"),
    PatchTarget("SSL_CTX_set_cert_verify_callback", 0x34110, -1, "Disable cert verify callback (noop)"),
]

# ============================================================================
# LIBNSS3.SO - NSS Library (used by Qt WebEngine)
# ============================================================================
LIBNSS_PATCHES = [
    PatchTarget("CERT_VerifyCertificate", 0x2e960, 0, "Main NSS cert verification"),
    PatchTarget("CERT_VerifyCertificateNow", 0x2ef60, 0, "Immediate NSS verification"),
    PatchTarget("CERT_VerifyCert", 0x2d360, 0, "Legacy NSS verification"),
    PatchTarget("CERT_VerifyCertNow", 0x2d380, 0, "Legacy immediate NSS verification"),
    PatchTarget("CERT_PKIXVerifyCert", 0x2abc0, 0, "PKIX path validation"),
    PatchTarget("CERT_VerifyCertName", 0x70e80, 0, "Hostname verification"),
    PatchTarget("CERT_VerifyOCSPResponseSignature", 0x25900, 0, "OCSP verification"),
    PatchTarget("CERT_VerifyCACertForUsage", 0x2c900, 0, "CA cert verification"),
]


def patch_library(input_path: str, output_path: str, patches: List[PatchTarget], lib_name: str) -> int:
    """Patch a library with the given patch targets"""
    
    print(f"\n{'='*70}")
    print(f"Patching {lib_name}: {input_path}")
    print(f"{'='*70}\n")
    
    if not os.path.exists(input_path):
        print(f"  [ERROR] File not found: {input_path}")
        return 0
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    file_size = len(data)
    print(f"  File size: {file_size} bytes (0x{file_size:x})\n")
    
    patched = 0
    
    for target in patches:
        if target.offset >= file_size:
            print(f"  [SKIP] {target.name}: offset 0x{target.offset:x} beyond file size")
            continue
        
        original = data[target.offset:target.offset+12]
        
        # Determine patch type
        if target.return_value == -1:
            patch = make_noop_patch()
        else:
            patch = make_return_patch(target.return_value)
        
        print(f"  {target.name} @ 0x{target.offset:x}")
        print(f"    Description: {target.description}")
        print(f"    Original:    {original[:8].hex()}")
        
        # Verify we're patching code (should start with endbr64 or common prologue)
        if original[:4] != bytes([0xf3, 0x0f, 0x1e, 0xfa]):
            # Check for other common prologues
            if original[0] not in [0x55, 0x41, 0x48, 0x53]:  # push rbp, push r*, sub/mov, push rbx
                print(f"    [WARN] Unexpected prologue, patching anyway")
        
        # Apply patch
        data[target.offset:target.offset+len(patch)] = patch
        print(f"    Patched:     {patch[:8].hex()}")
        patched += 1
        print()
    
    # Write output
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"  Patched {patched}/{len(patches)} functions")
    print(f"  Output: {output_path}")
    
    return patched


def create_complete_bypass(extraction_dir: str, output_dir: str):
    """Create complete SSL bypass by patching all libraries"""
    
    print("\n" + "#"*70)
    print("#" + " "*20 + "COMPLETE SSL BYPASS PATCHER" + " "*21 + "#")
    print("#" + " "*14 + "Based on Ghidra Analysis of OctoBrowser" + " "*15 + "#")
    print("#"*70 + "\n")
    
    os.makedirs(output_dir, exist_ok=True)
    
    total_patched = 0
    
    # Patch libcrypto.so.3
    crypto_src = os.path.join(extraction_dir, 'libcrypto.so.3')
    crypto_dst = os.path.join(output_dir, 'libcrypto.so.3')
    total_patched += patch_library(crypto_src, crypto_dst, LIBCRYPTO_PATCHES, "libcrypto.so.3")
    
    # Patch libssl.so.3
    ssl_src = os.path.join(extraction_dir, 'libssl.so.3')
    ssl_dst = os.path.join(output_dir, 'libssl.so.3')
    total_patched += patch_library(ssl_src, ssl_dst, LIBSSL_PATCHES, "libssl.so.3")
    
    # Patch libnss3.so
    nss_src = os.path.join(extraction_dir, 'libnss3.so')
    nss_dst = os.path.join(output_dir, 'libnss3.so')
    total_patched += patch_library(nss_src, nss_dst, LIBNSS_PATCHES, "libnss3.so")
    
    # Summary
    print("\n" + "="*70)
    print(f"COMPLETE SSL BYPASS: {total_patched} functions patched")
    print("="*70)
    print(f"\nPatched libraries saved to: {output_dir}")
    print("\nTo install:")
    print(f"  cp {output_dir}/*.so* {extraction_dir}/")
    
    return total_patched


def install_patches(patched_dir: str, target_dir: str):
    """Install patched libraries to target directory"""
    
    print(f"\nInstalling patched libraries to: {target_dir}")
    
    for lib in ['libcrypto.so.3', 'libssl.so.3', 'libnss3.so']:
        src = os.path.join(patched_dir, lib)
        dst = os.path.join(target_dir, lib)
        
        if os.path.exists(src):
            # Backup original
            if os.path.exists(dst) and not os.path.exists(dst + '.original'):
                shutil.copy2(dst, dst + '.original')
            
            shutil.copy2(src, dst)
            print(f"  [OK] {lib}")
        else:
            print(f"  [SKIP] {lib} not found")
    
    # Also install to nss subdirectory if it exists
    nss_dir = os.path.join(target_dir, 'nss')
    if os.path.isdir(nss_dir):
        nss_src = os.path.join(patched_dir, 'libnss3.so')
        nss_dst = os.path.join(nss_dir, 'libnss3.so')
        if os.path.exists(nss_src):
            shutil.copy2(nss_src, nss_dst)
            print(f"  [OK] nss/libnss3.so")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <extraction_dir> [output_dir]")
        print(f"       {sys.argv[0]} --install <patched_dir> <target_dir>")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} /tmp/OctoBrowser.AppImage_extracted")
        print(f"  {sys.argv[0]} --install /tmp/octo_patched_libs /tmp/_MEIxxxxx")
        sys.exit(1)
    
    if sys.argv[1] == '--install':
        if len(sys.argv) < 4:
            print("Usage: --install <patched_dir> <target_dir>")
            sys.exit(1)
        install_patches(sys.argv[2], sys.argv[3])
    else:
        extraction_dir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else '/tmp/octo_patched_libs'
        create_complete_bypass(extraction_dir, output_dir)


if __name__ == '__main__':
    main()
