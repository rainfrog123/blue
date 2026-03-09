# OctoBrowser Fingerprint Research

Research findings from testing OctoBrowser fingerprint generation and detection bypass.

## Overview

This document covers:
- Profile creation with custom fingerprints (Mac, Windows, Android)
- Fingerprint comparison between profiles
- Detection testing on BrowserScan and PixelScan
- Bypass strategies for antidetect detection
- Font fingerprinting limitations on Linux
- Android mobile profile support

### Supported OS Types

| OS | API Value | Architecture |
|----|-----------|--------------|
| Windows | `win` | `x86` |
| macOS | `mac` | `arm` |
| Android | `android` | `arm` |

---

## Profile Creation

### Best Method: Boilerplate Approach

The recommended way to create profiles with full control:

```python
import requests

API = "http://localhost:59999"

def create_profile(title: str, os_type: str = "mac") -> str:
    # 1. Get boilerplate fingerprint
    os_arch = "arm" if os_type == "mac" else "x86"
    resp = requests.post(
        f"{API}/api/v2/profiles/boilerplate/quick",
        json={"os": os_type, "os_arch": os_arch, "count": 1}
    )
    bp = resp.json()["data"]["boilerplates"][0]
    fp = bp["fp"]
    
    # 2. Fix null dns field (REQUIRED)
    fp["dns"] = ""
    
    # 3. Create profile
    payload = {
        "title": title,
        "name": title,  # This becomes the displayed title
        "description": bp.get("description", ""),
        "start_pages": bp.get("start_pages", []),
        "bookmarks": bp.get("bookmarks", []),
        "launch_args": bp.get("launch_args", []),
        "logo": bp.get("logo", ""),
        "tags": bp.get("tags", []),
        "fp": fp,
        "proxy": {"type": "direct"},
        "proxies": bp.get("proxies", []),
        "local_cache": bp.get("local_cache", False),
        "storage_options": bp.get("storage_options", {}),
    }
    
    resp = requests.post(f"{API}/api/v2/profiles", json=payload)
    return resp.json()["data"]["uuid"]
```

### Key Requirements

| Field | Requirement |
|-------|-------------|
| `name` | Set to custom title (becomes displayed title) |
| `fp.dns` | Must be `""` not `null` |
| `proxy` | Dict with `{"type": "direct"}` |
| `proxies` | Empty list `[]` |
| `logo` | Must be 32+ chars (use from boilerplate) |

### Quick Create (Limited)

```python
POST /api/v2/profiles/quick
{"title": "My Profile", "os": "mac"}
```

**Problem:** Ignores custom title - generates random names.

---

## Android Profile Creation

Android/mobile profiles have special requirements:

### Create Android Profile

```python
def create_android_profile(title: str) -> str:
    # 1. Get Android boilerplate
    resp = requests.post(
        f"{API}/api/v2/profiles/boilerplate/quick",
        json={"os": "android", "os_arch": "arm", "count": 1}
    )
    bp = resp.json()["data"]["boilerplates"][0]
    fp = bp["fp"]
    
    # 2. Fix null dns field
    if fp.get("dns") is None:
        fp["dns"] = ""
    
    # 3. Enable noise (optional)
    fp["noise"] = {
        "webgl": True,
        "canvas": True,
        "audio": True,
        "client_rects": True
    }
    
    # 4. CRITICAL: Disable extensions for mobile
    storage_opts = bp.get("storage_options", {})
    storage_opts["extensions"] = False  # Required for mobile!
    
    # 5. Create profile
    payload = {
        "title": title,
        "name": title,
        "description": bp.get("description", ""),
        "start_pages": bp.get("start_pages", []),
        "bookmarks": bp.get("bookmarks", []),
        "launch_args": bp.get("launch_args", []),
        "logo": bp.get("logo", ""),
        "tags": bp.get("tags", []),
        "fp": fp,
        "proxy": {"type": "direct"},
        "proxies": bp.get("proxies", []),
        "local_cache": bp.get("local_cache", False),
        "storage_options": storage_opts,
        "extensions": [],  # Empty for mobile
    }
    
    resp = requests.post(f"{API}/api/v2/profiles", json=payload)
    return resp.json()["data"]["uuid"]
```

### Android Fingerprint Fields

| Field | Example Value |
|-------|---------------|
| `os` | `android` |
| `os_version` | `13` |
| `device_model` | `SM-G780G`, `CPH2109`, `IN2025` |
| `device_type` | `phone` |
| `renderer` | `Android Renderer` |
| `user_agent` | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36...` |

### Mobile Profile Requirements

| Requirement | Value | Why |
|-------------|-------|-----|
| `storage_options.extensions` | `False` | Mobile Chrome doesn't support extensions |
| `extensions` | `[]` | Must be empty list |

**Error if not set:** `"Mobile profiles don't support extensions"` (code: `SN05`)

---

## Fingerprint Uniqueness

### Same OS - Different Fingerprints

Even when requesting multiple fingerprints for the same OS in a single API call (`count=2`), OctoBrowser generates **unique fingerprints**:

| Field | Fingerprint 1 | Fingerprint 2 |
|-------|---------------|---------------|
| OS | mac | mac |
| OS Arch | arm | arm |
| **OS Version** | **15** | **13** |
| **Screen** | **1512x982** | **1680x1050** |
| CPU Cores | 8 | 8 |
| **RAM** | **16 GB** | **64 GB** |
| **GPU** | **Apple M2** | **Apple M1** |
| **Fonts** | **436** | **428** |
| **Name** | possessive-gutter | murky-access |

### What Varies Between Profiles

1. **Screen resolution** - Different display sizes
2. **Font subsets** - Each has ~10-20 unique fonts from OS font pool
3. **OS version** - Minor version differences
4. **Hardware specs** - RAM, GPU model
5. **Auto-generated name** - Always unique

---

## Detection Testing

### BrowserScan Results

**URL:** https://www.browserscan.net/

| Profile | Score | Bot | Proxy | WebRTC |
|---------|-------|-----|-------|--------|
| Mac ARM #1 | **100%** | Pass | No | No leak |
| Mac ARM #2 | **100%** | Pass | No | No leak |

**Key Differences Detected:**

| Metric | Profile 1 | Profile 2 |
|--------|-----------|-----------|
| Chrome Version | 145.0.7632.**160** | 145.0.7632.**161** |
| macOS Version | **14.5.0** | **14.4.1** |
| DNS Servers | 40.78.232.123 | 23.98.80.64 |

**Conclusion:** BrowserScan rates both profiles as **100% authentic**.

---

### PixelScan Results

**URL:** https://pixelscan.net/fingerprint-check

#### Test Matrix (All OS Types)

| Profile | Fingerprint | Proxy | Masking | Bot |
|---------|-------------|-------|---------|-----|
| Mac-FullNoise-1 | ❌ | ❌ | ❌ Detected | ✓ |
| Mac-FullNoise-2 | ❌ | ❌ | ❌ Detected | ✓ |
| Mac-FullNoise-3 | ❌ | ❌ | ❌ Detected | ✓ |
| **Win-AllNoise** | ❌ | ❌ | **✓ Pass** | ✓ |
| **Win-NoNoise** | ❌ | ❌ | **✓ Pass** | ✓ |
| **Android-FullNoise** | ❌ | ❌ | **✓ Pass** | ✓ |

#### Key Findings

1. **Windows profiles pass Masking detection** - PixelScan doesn't detect them as antidetect browsers
2. **Android profiles also pass Masking detection** - Same as Windows
3. **Mac profiles always detected** - Masking detected regardless of noise settings
4. **All fail Proxy** - Microsoft datacenter IP detected
5. **All pass Bot check** - No automation detected
6. **Fingerprint "inconsistent"** - Due to datacenter IP, not fingerprint quality
7. **Noise doesn't help Mac** - Full noise enabled still results in masking detection

#### Detailed Fingerprint Comparison (Mac Profiles with Full Noise)

| Attribute | Profile 1 | Profile 2 | Profile 3 |
|-----------|-----------|-----------|-----------|
| Screen | 3456x2234 | 2880x1800 | 3360x2100 |
| GPU | Apple M1 | Apple M3 | Apple M1 |
| WebGL Hash | `4997916a...` | `41689ac7...` | `db9abf75...` |
| Canvas Hash | `4a14fa00...` | `a736cff4...` | `dae07402...` |
| Audio Hash | `dae23152...` | `1ae23a4e...` | `248194bc...` |
| **Font Hash** | **Same** | **Same** | **Same** |

**Note:** Noise IS working (hashes differ), but Mac fingerprints are still detected.

#### Android Profile PixelScan Results

| Attribute | Value |
|-----------|-------|
| Platform | Linux armv81 |
| User-Agent | `Mozilla/5.0 (Linux; Android 10; K)...` |
| Screen | 1080x2376 (360x792 available) |
| WebGL Renderer | Adreno (TM) 650 |
| WebGL Vendor | Qualcomm |
| Font Hash | `d41d8cd98f00b204e9800998ecf8427e` (empty) |
| **Masking** | **Not detected** |

---

## Font Fingerprinting on Linux

### Why Font Hashes Are Identical

When running OctoBrowser on Linux, all Mac profiles produce **identical font hashes** on PixelScan despite having different declared font lists.

#### How Font Detection Works

1. **PixelScan probes fonts** by rendering text in each declared font
2. **Compares to fallback** - if rendering matches fallback, font doesn't exist
3. **Generates hash** from actually detected fonts, not declared list

#### The Problem

| Factor | Value |
|--------|-------|
| Linux system fonts | ~226 fonts (DejaVu, Ubuntu, Liberation) |
| Mac fonts declared | ~400+ fonts (Al Bayan, Hiragino, Apple Chancery) |
| Mac fonts actually installed | **0** |

```
OctoBrowser declares: "Al Bayan" → Renders as: DejaVu Sans (fallback) → Detected: No
OctoBrowser declares: "Hiragino Sans" → Renders as: DejaVu Sans (fallback) → Detected: No
OctoBrowser declares: "Arial" → Renders as: Arial → Detected: Yes
```

**Result:** All profiles on same Linux system have identical font hash because only common fonts (Arial, Courier New, etc.) are actually present.

#### Font Hash Values

| OS Type | Font Hash | Reason |
|---------|-----------|--------|
| Mac (on Linux) | `008126315dbcb8838000381df5a4ad9c` | Only common fonts detected |
| Android | `d41d8cd98f00b204e9800998ecf8427e` | MD5 of empty string - no fonts |

#### Solutions

| Solution | Feasibility |
|----------|-------------|
| Install Mac fonts on Linux | Not legal/practical |
| Use Windows fingerprint | Windows fonts more common |
| Use Android fingerprint | Mobile has no font detection |
| Accept identical hashes | All profiles on same host will match |

---

## Fingerprint Configuration Options

### Noise Settings

Enable fingerprint randomization:

```python
fp["noise"] = {
    "webgl": True,
    "canvas": True,
    "audio": True,
    "client_rects": True
}
```

### WebRTC Options

```python
# Auto from proxy IP
fp["webrtc"] = {"type": "ip", "data": None}

# Use real IP
fp["webrtc"] = {"type": "real", "data": None}

# Disable non-proxied UDP
fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}
```

### Language/Timezone/Geolocation

```python
# Auto from IP
fp["languages"] = {"type": "ip", "data": None}
fp["timezone"] = {"type": "ip", "data": None}
fp["geolocation"] = {"type": "ip", "data": None}

# Manual
fp["languages"] = {"type": "manual", "data": ["en-US", "en"]}
fp["timezone"] = {"type": "manual", "data": "Asia/Singapore"}
```

---

## Bypass Strategies

### What Works

| Strategy | BrowserScan | PixelScan Masking |
|----------|-------------|-------------------|
| **Windows fingerprint** | ✓ 100% | ✓ Not detected |
| **Android fingerprint** | ✓ 100% | ✓ Not detected |
| Mac fingerprint | ✓ 100% | ❌ Detected |
| Noise enabled (Mac) | No difference | Still detected |
| WebRTC disabled | No difference | No difference |

### What Doesn't Work

| Issue | Reason | Solution |
|-------|--------|----------|
| Proxy detected | Datacenter IP | Use residential proxy |
| Fingerprint inconsistent | Due to proxy detection | Fix proxy first |
| Mac masking detected | PixelScan's algorithm | Use Windows or Android |
| Mac + Full noise | Noise doesn't prevent detection | Switch OS type |

### Recommended Configurations

#### Desktop (Best for general use)

```python
# Use Windows fingerprint
os_type = "win"
os_arch = "x86"

# Enable all noise
fp["noise"] = {
    "webgl": True,
    "canvas": True, 
    "audio": True,
    "client_rects": True
}

# Disable WebRTC leaks
fp["webrtc"] = {"type": "disable_non_proxied_udp", "data": None}

# Use residential proxy (not datacenter)
# NOTE: For profile creation API, use this format:
proxy = {
    "type": "new",
    "data": {
        "type": "http",  # or "socks5"
        "ip": "residential-proxy.com",  # Use "ip" not "host"
        "port": 1080,
        "login": "user",
        "password": "pass"
    }
}
```

#### Mobile (For mobile-specific sites)

```python
# Use Android fingerprint
os_type = "android"
os_arch = "arm"

# Enable noise
fp["noise"] = {
    "webgl": True,
    "canvas": True,
    "audio": True,
    "client_rects": True
}

# CRITICAL for mobile
storage_opts["extensions"] = False
extensions = []
```

---

## API Port Configuration

Default port: `59999` (configured in `start_octo.sh`)

### Change Port

1. Edit `/allah/blue/web/auto/octo/start_octo.sh`:
   ```bash
   OCTO_PORT=59999
   ```

2. Or write directly to port file:
   ```bash
   echo "59999" > ~/.Octo\ Browser/local_port
   ```

3. Restart OctoBrowser

### Port File Location

```
~/.Octo Browser/local_port
```

Config reads this dynamically - no code changes needed.

---

## Summary

### Detection Bypass Score Card

| Test Site | Mac | Windows | Android |
|-----------|-----|---------|---------|
| BrowserScan | ✓ 100% | ✓ 100% | ✓ 100% |
| PixelScan - Masking | ❌ Detected | ✓ Pass | ✓ Pass |
| PixelScan - Bot | ✓ Pass | ✓ Pass | ✓ Pass |
| PixelScan - Proxy | ❌ Datacenter | ❌ Datacenter | ❌ Datacenter |

### OS Type Recommendations

| Use Case | Recommended OS | Reason |
|----------|----------------|--------|
| General automation | Windows | Bypasses masking, most compatible |
| Mobile sites | Android | Mobile UA, bypasses masking |
| Apple-specific | Mac | Risk: masking detected |

### Key Findings

1. **Windows and Android bypass PixelScan** masking detection
2. **Mac is always detected** regardless of noise settings
3. **Noise randomizes hashes** but doesn't prevent Mac detection
4. **Font hashes are identical** on Linux due to missing Mac fonts
5. **Residential proxies required** to pass proxy detection
6. **Each profile is unique** - hardware specs, screen, GPU vary
7. **Android has no fonts** - empty font hash is expected

### Recommendations

1. **Use Windows or Android** for PixelScan bypass
2. **Use residential proxies** to avoid proxy detection
3. **Enable noise** for hash randomization between sessions
4. **Disable WebRTC** non-proxied UDP to prevent leaks
5. **Don't use Mac** if PixelScan bypass is required
6. **Mobile profiles** need `storage_options.extensions = False`

---

## Files

| File | Purpose |
|------|---------|
| `test/test_profile_creation.py` | Test profile creation with custom titles |
| `docs/octo_local_api.md` | Full API documentation |
| `octo_helpers.py` | Helper functions for profile management |

---

## Appendix: Full PixelScan Test Data

### Mac Profile Fingerprints (Full Noise Enabled)

| Attribute | Profile 1 | Profile 2 | Profile 3 |
|-----------|-----------|-----------|-----------|
| OS | Mac OS | Mac OS | Mac OS |
| Chrome | 145.0.0.0 | 145.0.0.0 | 145.0.0.0 |
| Platform | MacIntel | MacIntel | MacIntel |
| Screen | 3456x2234 | 2880x1800 | 3360x2100 |
| Available | 1728x1009 | 1440x781 | 1680x956 |
| CPU Cores | 8 | 8 | 8 |
| GPU | Apple M1 | Apple M3 | Apple M1 |
| WebGL Hash | `4997916a34fa82d65a1cb57aaae01d8a` | `41689ac752ec574c4290345401bb7e60` | `db9abf7550b97d932f1560f4cf656dcd` |
| Canvas Hash | `4a14fa0089ed8b6cbaf619eb4a278605` | `a736cff46e9327695e065dec0790f52e` | `dae07402b2a8d41cba71ad6fff461eb5` |
| Audio Hash | `dae231527bd79ec266f6cca6f7e5dd24` | `1ae23a4e3c42af6b3316896d0caf8b1d` | `248194bc03163134393b1c32f4dbd05b` |
| Font Hash | `008126315dbcb8838000381df5a4ad9c` | Same | Same |
| **Masking** | ❌ Detected | ❌ Detected | ❌ Detected |

### Android Profile Fingerprint

| Attribute | Value |
|-----------|-------|
| OS | Android |
| Chrome | 145.0.0.0 Mobile |
| Platform | Linux armv81 |
| User-Agent | `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36` |
| Screen | 1080x2376 |
| Available | 360x792 |
| CPU Cores | 8 |
| WebGL Renderer | Adreno (TM) 650 |
| WebGL Vendor | Qualcomm |
| WebGL Hash | `4997916a34fa82d65a1cb57aaae01d8a` |
| Canvas Hash | `799a4c6005e39b391aeb25d1dae573e5` |
| Audio Hash | `a43620557dd95482c8e2d375c6eaf984` |
| Font Hash | `d41d8cd98f00b204e9800998ecf8427e` |
| **Masking** | ✓ Not detected |

---

## References

- [BrowserScan](https://www.browserscan.net/) - 100% authenticity check
- [PixelScan](https://pixelscan.net/fingerprint-check) - Antidetect detection
- [OctoBrowser API Docs](https://documenter.getpostman.com/view/1801428/UVC6i6eA)
