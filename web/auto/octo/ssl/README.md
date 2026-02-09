# SSL Pinning Bypass for OctoBrowser

Tools and documentation for bypassing SSL/TLS certificate pinning in OctoBrowser.

## Quick Start

```bash
# Option 1: All-in-one script
./patch_and_run_octo.sh

# Option 2: Manual steps
# 1. Start mitmproxy
mitmdump -p 8080 --ssl-insecure -w /tmp/octo_traffic.flow &

# 2. Run patched OctoBrowser
python3 ghidra_ssl_patcher.py /tmp/OctoBrowser.AppImage_extracted /tmp/octo_patched_libs
cp /tmp/octo_patched_libs/*.so /tmp/OctoBrowser.AppImage_extracted/
DISPLAY=:1 proxychains4 /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox

# 3. Read captured traffic
mitmdump -r /tmp/octo_traffic.flow --flow-detail 3
```

## SSL Libraries in OctoBrowser

| Library | Purpose |
|---------|---------|
| `libnss3.so` | Mozilla NSS - main cert verification |
| `libssl.so.3` | OpenSSL SSL/TLS |
| `libcrypto.so.3` | OpenSSL crypto primitives |
| `libQt6WebEngineCore.so.6` | Qt WebEngine (Chromium) |

## Patched Functions

### libnss3.so (NSS)

| Function | Offset | Patch | Purpose |
|----------|--------|-------|---------|
| `CERT_VerifyCertificate` | 0x2e960 | returns 0 | Main cert verification |
| `CERT_VerifyCertificateNow` | 0x2ef60 | returns 0 | Immediate verification |
| `CERT_VerifyCert` | 0x2d360 | returns 0 | Legacy wrapper |
| `CERT_VerifyCertNow` | 0x2d380 | returns 0 | Legacy immediate |
| `CERT_PKIXVerifyCert` | 0x2abc0 | returns 0 | PKIX path validation |
| `CERT_VerifyCertName` | 0x70e80 | returns 0 | Hostname verification |
| `CERT_VerifyOCSPResponseSignature` | 0x25900 | returns 0 | OCSP verification |
| `CERT_VerifyCACertForUsage` | 0x2c900 | returns 0 | CA cert verification |

### libssl.so.3 (OpenSSL)

| Function | Offset | Patch | Purpose |
|----------|--------|-------|---------|
| `SSL_get_verify_result` | 0x34840 | returns 0 | Returns X509_V_OK |
| `SSL_CTX_set_verify` | 0x34130 | noop | Disable verify callback |
| `SSL_CTX_set_cert_verify_callback` | 0x34110 | noop | Disable cert callback |

### libcrypto.so.3 (OpenSSL Crypto)

| Function | Offset | Patch | Purpose |
|----------|--------|-------|---------|
| `X509_verify_cert` | 0x2396e0 | returns 1 | X509 chain verification |
| `X509_verify` | 0x237760 | returns 1 | Signature verification |
| `X509_STORE_CTX_verify` | 0x239b50 | returns 1 | Store context verify |

### libQt6WebEngineCore.so.6 (Qt)

| Function | Offset | Patch | Purpose |
|----------|--------|-------|---------|
| `rejectCertificate` | 0x55df580 | jmp acceptCertificate | Critical Qt bypass |

## Patch Explanation

```asm
; Original function start:
f3 0f 1e fa          endbr64           ; Intel CET landing pad
41 57                push r15          ; Save registers
...                                    ; Verification logic

; Patched function:
f3 0f 1e fa          endbr64           ; Keep CET landing pad
31 c0                xor eax, eax      ; Return 0 (SECSuccess)
c3                   ret               ; Return immediately
90                   nop               ; Padding
```

## Files

| File | Purpose |
|------|---------|
| `ghidra_ssl_patcher.py` | Main patcher for NSS |
| `ghidra_complete_ssl_bypass.py` | Complete patcher (all libs) |
| `patch_nss.py` | NSS-specific patcher |
| `patch_openssl.py` | OpenSSL-specific patcher |
| `frida_ssl_bypass*.js` | Frida scripts (unstable) |
| `frida_nss_bypass*.js` | NSS-specific Frida hooks |
| `patch_and_run_octo.sh` | All-in-one launcher |
| `ssl_bypass.c` | LD_PRELOAD library |

## Ghidra Analysis

```bash
# Analyze libnss3.so
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_projects OctoSSL \
  -import /tmp/OctoBrowser.AppImage_extracted/libnss3.so

# GUI analysis
DISPLAY=:1 /opt/ghidra/ghidraRun
# 1. Import libnss3.so
# 2. Search > For Strings > "certificate"
# 3. Navigate to CERT_VerifyCertificate
# 4. Analyze control flow
```

## Bypass Methods Attempted

### 1. Frida Runtime Hooking
**Result**: PARTIAL - causes crashes
- Frida can attach and hook functions
- OctoBrowser crashes due to anti-debugging
- Error: `segfault in memfd:frida-agent-64.so`

### 2. Binary Patching
**Result**: WORKS - but requires pre-extraction
- Patch libraries before they're loaded
- Use `ghidra_ssl_patcher.py`

### 3. LD_PRELOAD
**Result**: FAILS - AppImage blocks it
- PyInstaller's bootloader ignores LD_PRELOAD
- AppImage's FUSE filesystem interferes

### 4. Proxychains
**Result**: PARTIAL - routes traffic but TLS fails
- Traffic is routed through proxy
- Certificate pinning still blocks interception

## The PyInstaller Challenge

OctoBrowser is a PyInstaller AppImage:
1. Bootloader extracts to `/tmp/_MEI*`
2. Libraries are immediately loaded
3. Patches must be applied before execution

### Solution: Pre-patch the extraction

```bash
# Extract permanently
python3 pyinstxtractor.py OctoBrowser.AppImage

# Patch in extraction directory
python3 ghidra_ssl_patcher.py /tmp/OctoBrowser.AppImage_extracted /tmp/patched
cp /tmp/patched/*.so /tmp/OctoBrowser.AppImage_extracted/

# Run from extraction
cd /tmp/OctoBrowser.AppImage_extracted
./main
```

## Verify Traffic Interception

```bash
# Read captured traffic
mitmdump -r /tmp/octo_traffic.flow --flow-detail 3

# Filter specific domains
mitmdump -r /tmp/octo_traffic.flow "~d octobrowser"

# Export as HAR
mitmdump -r /tmp/octo_traffic.flow --export.har traffic.har
```

## Troubleshooting

### App crashes immediately
```bash
# Restore original library
cp /tmp/OctoBrowser.AppImage_extracted/libnss3.so.bak \
   /tmp/OctoBrowser.AppImage_extracted/libnss3.so
```

### SSL still fails
```bash
# Check which SSL libs are loaded
strace -f -e openat /home/vncuser/Downloads/OctoBrowser.AppImage 2>&1 | grep -i ssl
```

### Proxy not receiving traffic
```bash
# Verify proxychains config
cat /etc/proxychains4.conf | grep -v "^#" | grep -v "^$"
```

### Verify patch was applied
```bash
xxd -s 0x2e960 -l 8 /tmp/OctoBrowser.AppImage_extracted/libnss3.so
# Expected: f30f 1efa 31c0 c390
```
