#!/usr/bin/env python3
"""
Patch libnss3.so to disable certificate verification
Patches CERT_Verify* functions to immediately return SECSuccess (0)
"""
import sys
import shutil

def patch_library(lib_path, output_path=None):
    if output_path is None:
        output_path = lib_path + ".patched"
    
    # Copy original
    shutil.copy2(lib_path, output_path)
    
    # Functions to patch (offset, name)
    # These offsets are after the endbr64 instruction (4 bytes)
    functions_to_patch = [
        (0x2e964, "CERT_VerifyCertificate"),
        (0x2ef64, "CERT_VerifyCertificateNow"),
        (0x2d364, "CERT_VerifyCert"),
        (0x2c904, "CERT_VerifyCACertForUsage"),  # 0x2c900 + 4
        (0x70e84, "CERT_VerifyCertName"),  # 0x70e80 + 4
    ]
    
    # Patch bytes: xor eax, eax; ret (return 0)
    # 31 c0 = xor eax, eax
    # c3    = ret
    patch = b'\x31\xc0\xc3'
    
    with open(output_path, 'r+b') as f:
        for offset, name in functions_to_patch:
            f.seek(offset)
            original = f.read(3)
            f.seek(offset)
            f.write(patch)
            print(f"Patched {name} at 0x{offset:x}: {original.hex()} -> {patch.hex()}")
    
    print(f"\nPatched library saved to: {output_path}")
    return output_path

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 patch_nss.py <libnss3.so> [output_path]")
        sys.exit(1)
    
    lib_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    patch_library(lib_path, output_path)
