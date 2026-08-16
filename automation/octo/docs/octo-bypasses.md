# OctoBrowser Bypass Guides

Reverse engineering guides for bypassing API tier restrictions and SSL certificate pinning.

---

# Part 1: API Tier Bypass

## The Problem

Local API (`http://localhost:59999`) requires a paid tier. Free/Starter plans get:

```
Error: FEATURE_IS_DISABLED_FOR_YOUR_PLAN
Code: feature_is_disabled_for_your_plan
```

## Key Files

| File | Contains |
|------|----------|
| `octo/fastapi/dependencies.pyc` | Feature checks |
| `octo/fastapi/routers/automation/dependencies.pyc` | Automation tier check |
| `octo/auth/state.pyc` | Subscription state |
| `octo/api_error_codes.pyc` | Error definitions |

## Finding the Check

```bash
strings PYZ.pyz_extracted/octo/*.pyc | grep -i "feature.*disabled"
# FEATURE_IS_DISABLED_FOR_YOUR_PLAN, SubscriptionFeatureDisabledException

uncompyle6 octo/fastapi/routers/automation/dependencies.pyc
# Look for: if not subscription.has_feature("automation_api"): raise ...
```

## Bypass Methods

### 1. Patch Python Bytecode

Decompile → change `if not has_feature(...)` to `if False` → recompile → replace `.pyc` in extracted AppImage.

### 2. mitmproxy (Proxy Response Modification)

Intercept auth/subscription responses from `octobrowser.net`, inject `automation_api: true` and `plan_id: "team"` into JSON.

### 3. Local Storage Manipulation

Decrypt `localpersist.data` (see [octo_ghidra_guides.md](octo_ghidra_guides.md)), patch `subscription.features.automation_api = True`, re-encrypt.

### 4. Repack AppImage

After patching: `appimagetool OctoBrowser.AppImage_extracted OctoBrowser_patched.AppImage`

## Verification

```bash
curl http://localhost:59999/api/v2/automation/profiles
# Success: profile list. Failure: {"error": "feature_is_disabled_for_your_plan"}
```

---

# Part 2: SSL Pinning Bypass

## Quick Start

```bash
./patch_and_run_octo.sh

# Or manual:
python3 ghidra_ssl_patcher.py /tmp/OctoBrowser.AppImage_extracted /tmp/patched
cp /tmp/patched/*.so /tmp/OctoBrowser.AppImage_extracted/
mitmdump -p 8080 --ssl-insecure -w /tmp/octo_traffic.flow &
DISPLAY=:1 proxychains4 OctoBrowser.AppImage --no-sandbox
```

## SSL Libraries

| Library | Purpose |
|---------|---------|
| `libnss3.so` | NSS - main cert verification |
| `libssl.so.3` | OpenSSL SSL/TLS |
| `libcrypto.so.3` | OpenSSL crypto |
| `libQt6WebEngineCore.so.6` | Qt WebEngine |

## Patched Functions (libnss3.so)

| Function | Offset | Patch |
|----------|--------|-------|
| `CERT_VerifyCertificate` | 0x2e960 | returns 0 |
| `CERT_VerifyCertificateNow` | 0x2ef60 | returns 0 |
| `CERT_VerifyCert` | 0x2d360 | returns 0 |
| `CERT_PKIXVerifyCert` | 0x2abc0 | returns 0 |

Patch: `xor eax, eax; ret` (return SECSuccess).

## Bypass Methods

| Method | Result |
|--------|--------|
| Binary patching | WORKS — pre-patch extracted libs |
| Frida | PARTIAL — causes crashes |
| LD_PRELOAD | FAILS — AppImage blocks it |
| Proxychains | PARTIAL — routes traffic, TLS still fails |

## PyInstaller Constraint

Libraries load from `/tmp/_MEI*` at runtime. **Pre-patch** the extraction directory, then run `./main` from there.

## Files

| File | Purpose |
|------|---------|
| `ghidra_ssl_patcher.py` | Main NSS patcher |
| `patch_and_run_octo.sh` | All-in-one launcher |

## Troubleshooting

```bash
# Verify patch
xxd -s 0x2e960 -l 8 libnss3.so
# Expected: f30f 1efa 31c0 c390

# Restore original
cp libnss3.so.bak libnss3.so
```

---

## Disclaimer

For educational/research purposes. Bypassing license restrictions may violate terms of service.
