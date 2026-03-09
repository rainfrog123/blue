#!/usr/bin/env python3
"""
OctoBrowser OpenSSL SSL Pinning Bypass Patcher

Patches the OpenSSL libraries used by Qt/QtWebEngine to bypass certificate verification.

Key functions:
- X509_verify_cert in libcrypto.so.3 @ 0x2396e0 -> returns 1 (success)
- SSL_get_verify_result in libssl.so.3 @ 0x34840 -> returns 0 (X509_V_OK)
"""

import shutil
import sys
import os


def patch_libcrypto(input_path: str, output_path: str) -> bool:
    """Patch libcrypto.so.3 to bypass X509_verify_cert"""
    
    print(f"\n{'='*60}")
    print(f"Patching libcrypto.so.3: {input_path}")
    print(f"{'='*60}\n")
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    # X509_verify_cert @ 0x2396e0
    # Returns 1 on success, 0 on failure, -1 on error
    # Patch to always return 1
    offset = 0x2396e0
    
    original = data[offset:offset+16]
    print(f"  X509_verify_cert @ 0x{offset:x}")
    print(f"  Original: {original.hex()}")
    
    # Check for expected start (endbr64)
    if original[:4] != bytes([0xf3, 0x0f, 0x1e, 0xfa]):
        print(f"  [WARN] Unexpected bytes, patching anyway")
    
    # Patch: endbr64; mov eax, 1; ret; nops
    patch = bytes([
        0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
        0xb8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
        0xc3,  # ret
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90  # nop padding
    ])
    
    data[offset:offset+len(patch)] = patch
    print(f"  Patched:  {patch[:10].hex()}")
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"\n  Output: {output_path}")
    return True


def patch_libssl(input_path: str, output_path: str) -> bool:
    """Patch libssl.so.3 to bypass SSL_get_verify_result"""
    
    print(f"\n{'='*60}")
    print(f"Patching libssl.so.3: {input_path}")
    print(f"{'='*60}\n")
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    # SSL_get_verify_result @ 0x34840
    # Returns X509_V_OK (0) on success
    offset = 0x34840
    
    original = data[offset:offset+16]
    print(f"  SSL_get_verify_result @ 0x{offset:x}")
    print(f"  Original: {original.hex()}")
    
    # Patch: endbr64; xor eax, eax; ret; nops
    patch = bytes([
        0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
        0x31, 0xc0,              # xor eax, eax (return 0 = X509_V_OK)
        0xc3,                    # ret
        0x90,                    # nop
    ])
    
    data[offset:offset+len(patch)] = patch
    print(f"  Patched:  {patch.hex()}")
    
    # Also patch SSL_CTX_set_verify to do nothing (optional, but helps)
    # This prevents the verify callback from being set
    offset_set_verify = 0x34130
    original2 = data[offset_set_verify:offset_set_verify+8]
    print(f"\n  SSL_CTX_set_verify @ 0x{offset_set_verify:x}")
    print(f"  Original: {original2.hex()}")
    
    # Patch to just return (do nothing)
    patch2 = bytes([
        0xf3, 0x0f, 0x1e, 0xfa,  # endbr64
        0xc3,                    # ret
        0x90, 0x90, 0x90,        # nop padding
    ])
    data[offset_set_verify:offset_set_verify+len(patch2)] = patch2
    print(f"  Patched:  {patch2.hex()}")
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"\n  Output: {output_path}")
    return True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <extraction_dir> [output_dir]")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} /tmp/OctoBrowser.AppImage_extracted /tmp/octo_patched_libs")
        sys.exit(1)
    
    extraction_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else '/tmp/octo_patched_libs'
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Patch libcrypto.so.3
    crypto_src = os.path.join(extraction_dir, 'libcrypto.so.3')
    crypto_dst = os.path.join(output_dir, 'libcrypto.so.3')
    if os.path.exists(crypto_src):
        patch_libcrypto(crypto_src, crypto_dst)
    else:
        print(f"[ERROR] {crypto_src} not found")
    
    # Patch libssl.so.3
    ssl_src = os.path.join(extraction_dir, 'libssl.so.3')
    ssl_dst = os.path.join(output_dir, 'libssl.so.3')
    if os.path.exists(ssl_src):
        patch_libssl(ssl_src, ssl_dst)
    else:
        print(f"[ERROR] {ssl_src} not found")
    
    print(f"\n{'='*60}")
    print("OpenSSL patching complete!")
    print(f"{'='*60}")
    print(f"\nPatched libraries in: {output_dir}")
    print("\nTo use:")
    print(f"  cp {output_dir}/libcrypto.so.3 {extraction_dir}/")
    print(f"  cp {output_dir}/libssl.so.3 {extraction_dir}/")


if __name__ == '__main__':
    main()
