# Bypassing OctoBrowser API Tier Restrictions

A reverse engineering guide to understanding and bypassing OctoBrowser's subscription tier checks for local API access.

## The Problem

OctoBrowser's local automation API (`http://localhost:58888`) requires a paid subscription tier. Free/Starter plans get:

```
Error: FEATURE_IS_DISABLED_FOR_YOUR_PLAN
Code: feature_is_disabled_for_your_plan
```

This guide documents how to find and potentially bypass these restrictions using Ghidra and Python bytecode analysis.

## Phase 1: Understanding the Architecture

### 1.1 Local API Stack

```
┌─────────────────────────────────────────┐
│           OctoBrowser GUI               │
├─────────────────────────────────────────┤
│         FastAPI Server (uvicorn)        │
│         http://127.0.0.1:58888          │
├─────────────────────────────────────────┤
│    Subscription/Feature Validation      │  ← CHECK HAPPENS HERE
├─────────────────────────────────────────┤
│         Profile Management              │
│         Browser Automation              │
└─────────────────────────────────────────┘
```

### 1.2 Key Files in AppImage

```bash
# Extract and list relevant files
cd /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted

# API Layer
octo/fastapi/
├── app.pyc                    # FastAPI app setup
├── dependencies.pyc           # Request dependencies
├── middlewares.pyc            # Auth middleware
├── routers/
│   ├── automation/            # LOCAL API ENDPOINTS
│   │   ├── app.pyc
│   │   └── dependencies.pyc
│   ├── profiles/              # Profile management
│   └── ...

# Subscription/Auth
octo/auth/
├── state.pyc                  # Auth state (tokens, user)
└── controller.pyc             # Auth logic

# Error Codes
octo/api_error_codes.pyc       # All error constants
```

## Phase 2: Finding the Tier Check

### 2.1 String Search

```bash
# Find where feature checks happen
strings PYZ.pyz_extracted/octo/*.pyc | grep -i "feature.*disabled"

# Output:
# FEATURE_IS_DISABLED_FOR_YOUR_PLAN
# SubscriptionFeatureDisabledException
# feature_is_disabled_for_your_plan
```

### 2.2 Error Code Analysis

From `octo/api_error_codes.pyc`:

```python
class ServerErrorCodes(StrEnum):
    FEATURE_IS_DISABLED_FOR_YOUR_PLAN = "feature_is_disabled_for_your_plan"
    SUBSCRIPTION_INACTIVE = "subscriptions.inactive"
    SUBSCRIPTION_LIMITS_REACHED = "subscriptions.limits_reached"
    PROFILE_LIMIT_1 = "profiles.limit.1"
    RATE_LIMITED = "rate_limited"
```

### 2.3 Exception Classes

From `octo/fastapi/exceptions.pyc`:

```python
class SubscriptionFeatureDisabledException(AutoAPIException):
    """Raised when feature is not available for user's subscription plan"""
    
    def __init__(self):
        super().__init__(
            status_code=403,
            error_code="SUBSCRIPTION_FEATURE_DISABLED",
            message="Subscription feature disabled",
            legacy_error_code="subscription_feature_disabled"
        )
```

## Phase 3: Tracing the Validation Flow

### 3.1 Find Where Exception is Raised

```bash
# Search for raise statements with this exception
find PYZ.pyz_extracted -name "*.pyc" -exec strings {} \; | \
    grep -B5 -A5 "SubscriptionFeatureDisabled"
```

### 3.2 Decompile Key Files

Using `pycdc` or `uncompyle6`:

```bash
# Install decompiler
pip install uncompyle6

# Decompile the automation router
uncompyle6 octo/fastapi/routers/automation/app.pyc

# Decompile dependencies (where checks likely happen)
uncompyle6 octo/fastapi/routers/automation/dependencies.pyc
```

### 3.3 Subscription Check Pattern

The decompiled code reveals the check pattern:

```python
# Typical pattern in routers
async def some_endpoint(request: Request):
    # Get user subscription from auth state
    subscription = await get_user_subscription()
    
    # Check if feature is enabled for plan
    if not subscription.has_feature("automation_api"):
        raise SubscriptionFeatureDisabledException()
    
    # ... rest of endpoint logic
```

## Phase 4: Finding the Feature Flag

### 4.1 Subscription Data Structure

From `octo/auth/state.pyc`:

```python
@dataclass
class AuthStateData:
    uuid: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    email: Optional[str] = None
    # ... subscription data comes from server
```

### 4.2 Server Response Analysis

The subscription data comes from the server at login. Capture with mitmproxy:

```bash
mitmproxy -p 8080 --mode regular

# In another terminal, start OctoBrowser with proxy
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
/tmp/OctoBrowser.AppImage --no-sandbox
```

Server response includes:

```json
{
  "subscription": {
    "plan_id": "starter",
    "features": {
      "automation_api": false,
      "profiles_limit": 10,
      "api_access": false
    }
  }
}
```

## Phase 5: Bypass Methods

### Method 1: Patch the Python Bytecode

#### 5.1.1 Find the Check Function

```bash
# Locate the feature check
pycdc octo/fastapi/dependencies.pyc > dependencies_decompiled.py

# Look for patterns like:
# if not has_feature("automation"):
#     raise SubscriptionFeatureDisabledException()
```

#### 5.1.2 Patch Strategy

Convert the conditional to always pass:

```python
# Original
if not subscription.has_feature("automation_api"):
    raise SubscriptionFeatureDisabledException()

# Patched - make condition always false
if False:  # Never raises
    raise SubscriptionFeatureDisabledException()
```

#### 5.1.3 Recompile and Replace

```bash
# Compile patched Python
python3 -m py_compile dependencies_patched.py

# Replace in extracted AppImage
cp dependencies_patched.cpython-312.pyc \
   /tmp/OctoBrowser.AppImage_extracted/PYZ.pyz_extracted/octo/fastapi/dependencies.pyc

# Repack AppImage (complex - see below)
```

### Method 2: Hook at Runtime with Frida

#### 5.2.1 Frida Script

```javascript
// frida_bypass_tier.js
// Hook Python's feature check

Java.perform(function() {
    // Find the SubscriptionFeatureDisabledException class
    var PyObject = Java.use("org.python.core.PyObject");
    
    // Hook the check function
    // This is pseudocode - actual implementation depends on Python embedding
});

// Alternative: Hook the HTTP response
Interceptor.attach(Module.findExportByName(null, "recv"), {
    onLeave: function(retval) {
        // Modify subscription response to enable features
    }
});
```

```bash
frida -f /tmp/OctoBrowser.AppImage -- -l frida_bypass_tier.js
```

### Method 3: Proxy Response Modification

#### 5.3.1 mitmproxy Script

```python
# mitm_tier_bypass.py
from mitmproxy import http
import json

def response(flow: http.HTTPFlow):
    # Intercept subscription/auth responses
    if "octobrowser.net" in flow.request.host:
        if "/auth" in flow.request.path or "/subscription" in flow.request.path:
            try:
                data = json.loads(flow.response.content)
                
                # Inject premium features
                if "subscription" in data:
                    data["subscription"]["features"] = {
                        "automation_api": True,
                        "api_access": True,
                        "profiles_limit": 9999,
                        "proxy_limit": 9999
                    }
                    data["subscription"]["plan_id"] = "team"
                
                flow.response.content = json.dumps(data).encode()
                print(f"[+] Patched subscription response")
            except:
                pass
```

```bash
mitmproxy -s mitm_tier_bypass.py -p 8080
```

### Method 4: Local Storage Manipulation

#### 5.4.1 Understanding Storage Encryption

From the HID analysis, we know:
- Storage is encrypted with Fernet
- Key = PBKDF2(machine_id + "TeNtAcLeShErE___")

#### 5.4.2 Decrypt, Modify, Re-encrypt

```python
# modify_subscription.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json

def get_key(machine_id: str) -> bytes:
    password = (machine_id + "TeNtAcLeShErE___").encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'octo_salt',  # May vary
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def patch_storage():
    machine_id = open("/etc/machine-id").read().strip()
    key = get_key(machine_id)
    f = Fernet(key)
    
    # Read encrypted storage
    with open("/root/.Octo Browser/localpersist.data", "rb") as file:
        encrypted = file.read()
    
    # Decrypt
    data = json.loads(f.decrypt(encrypted))
    
    # Patch subscription
    if "subscription" in data:
        data["subscription"]["features"]["automation_api"] = True
        data["subscription"]["features"]["api_access"] = True
    
    # Re-encrypt and save
    with open("/root/.Octo Browser/localpersist.data", "wb") as file:
        file.write(f.encrypt(json.dumps(data).encode()))

if __name__ == "__main__":
    patch_storage()
```

### Method 5: Binary Patching with Ghidra

#### 5.5.1 Target: Python Interpreter Check

If the check is in native code (unlikely but possible):

```bash
# Launch Ghidra
DISPLAY=:1 /opt/ghidra/ghidraRun

# Import libpython3.12.so.1.0
# Search for "SubscriptionFeature" or "feature_disabled"
```

#### 5.5.2 Patch the Comparison

In Ghidra:
1. Find the comparison instruction (`CMP`, `TEST`)
2. Change `JZ` (jump if zero) to `JMP` (always jump)
3. Or NOP out the entire check

```asm
; Original
CMP    EAX, 0x1          ; Check feature flag
JZ     feature_disabled   ; Jump if not enabled

; Patched
CMP    EAX, 0x1
NOP                       ; Never jump
NOP
```

## Phase 6: Repacking the AppImage

### 6.1 After Patching Files

```bash
cd /tmp

# Install appimagetool
wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
chmod +x appimagetool-x86_64.AppImage

# Repack
./appimagetool-x86_64.AppImage OctoBrowser.AppImage_extracted OctoBrowser_patched.AppImage

# Make executable
chmod +x OctoBrowser_patched.AppImage
```

### 6.2 Run Patched Version

```bash
DISPLAY=:1 ./OctoBrowser_patched.AppImage --no-sandbox
```

## Phase 7: Verification

### 7.1 Test Local API

```bash
# Get the port (usually 58888)
cat ~/.Octo\ Browser/local_port

# Test API access
curl http://localhost:58888/api/v2/automation/profiles

# If successful, you'll get profile list instead of:
# {"error": "feature_is_disabled_for_your_plan"}
```

### 7.2 Common Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/automation/profiles` | GET | List profiles |
| `/api/v2/automation/profiles/{uuid}/start` | POST | Start profile |
| `/api/v2/automation/profiles/{uuid}/stop` | POST | Stop profile |
| `/api/v2/automation/profiles` | POST | Create profile |

## Appendix: Quick Reference

### Error Codes to Bypass

| Code | Meaning | Where Raised |
|------|---------|--------------|
| `FEATURE_IS_DISABLED_FOR_YOUR_PLAN` | Tier too low | Feature checks |
| `SUBSCRIPTION_INACTIVE` | No subscription | Auth middleware |
| `SUBSCRIPTION_LIMITS_REACHED` | Hit quota | Usage checks |
| `RATE_LIMITED` | Too many requests | Rate limiter |

### Files to Patch

| File | Contains |
|------|----------|
| `octo/fastapi/dependencies.pyc` | Request auth/feature checks |
| `octo/fastapi/middlewares.pyc` | Global middleware checks |
| `octo/auth/state.pyc` | Subscription state |
| `octo/api_error_codes.pyc` | Error definitions |

### Useful Tools

| Tool | Purpose |
|------|---------|
| `pycdc` | Decompile Python 3.12 bytecode |
| `uncompyle6` | Decompile older Python |
| `mitmproxy` | Intercept/modify HTTP |
| `frida` | Runtime hooking |
| `Ghidra` | Binary analysis |

## Disclaimer

This is for educational/research purposes. Bypassing license restrictions may violate terms of service.
