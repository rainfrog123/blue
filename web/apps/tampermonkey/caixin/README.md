# Caixin Login Mechanism

Documentation for the Caixin (财新) user authentication system.

## Project Structure

```
caixin/
├── README.md              # This documentation
├── .gitignore             # Git ignore rules
├── auth_cookies.json      # Saved auth data (gitignored)
├── har/                   # HAR (HTTP Archive) data files
│   ├── login.js           # Login request capture
│   └── xhr.js             # Full session capture
├── scripts/               # Python scripts
│   └── auth.py            # CLI authentication tool
└── userscripts/           # Tampermonkey userscripts
    ├── auto_relogin.js    # Auto re-login on session kick
    ├── simple_caixin.js   # Clean reading experience
    ├── caixin-en-filter.user.js
    └── copy.js
```

## Overview

Caixin supports two login methods:
1. **QR Code Login** - Scan with Caixin mobile app
2. **Username/Password Login** - Phone number + encrypted password (JSONP)

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/ucenter/user/v1/loginJsonp` | GET | Username/password login (JSONP) |
| `/api/ucenter/scan/v1/checkQRCodeStatus` | GET | Poll QR code scan status |
| `/api/ucenter/userinfo/get` | GET | Fetch user info after login |
| `/api/ucenter/inter/areacode` | GET | Get phone area codes |

Base URL: `https://gateway.caixin.com`

## Password Encryption

Caixin encrypts passwords client-side before transmission.

### Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-128 |
| Mode | ECB |
| Padding | PKCS7 |
| Key | `G3JH98Y8MY9GWKWG` |

### Encryption Flow

```
Plaintext Password
    ↓ AES-128-ECB encrypt (key: G3JH98Y8MY9GWKWG)
    ↓ Base64 encode
    ↓ URL encode
Final encrypted string
```

### Example

```
Input:  Aa@19282708311
Output: vKdw0DxaLEVJI%2BtTfSmRFQ%3D%3D
```

### JavaScript (CryptoJS)

```javascript
const CryptoJS = require('crypto-js');

function encryptPassword(password) {
    const key = CryptoJS.enc.Utf8.parse('G3JH98Y8MY9GWKWG');
    const plaintext = CryptoJS.enc.Utf8.parse(password);
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encodeURIComponent(encrypted.toString());
}
```

### Command Line (OpenSSL)

```bash
echo -n 'YOUR_PASSWORD' | openssl enc -aes-128-ecb \
    -K $(echo -n 'G3JH98Y8MY9GWKWG' | xxd -p) -a
```

### Python

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import urllib.parse

def encrypt_password(password):
    key = b'G3JH98Y8MY9GWKWG'
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(password.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded)
    b64 = base64.b64encode(encrypted).decode()
    return urllib.parse.quote(b64)
```

## Login API

### Request

```
GET https://gateway.caixin.com/api/ucenter/user/v1/loginJsonp
    ?account={phone_number}
    &password={encrypted_password}
    &deviceType=5
    &unit=1
    &areaCode=%2B86
    &extend={url_encoded_json}
    &callback=__caixincallback{timestamp}
```

### Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `account` | Phone number | `19282708311` |
| `password` | AES encrypted, URL encoded | `vKdw0DxaLEVJI%2BtTfSmRFQ%3D%3D` |
| `deviceType` | Device type (5 = web) | `5` |
| `unit` | Unit ID | `1` |
| `areaCode` | Country code | `%2B86` (+86) |
| `extend` | JSON metadata | `%7B%22resource_article%22%3A%22%22%7D` |
| `callback` | JSONP callback name | `__caixincallback1776017518675` |

### Response

JSONP response wrapping JSON:

```javascript
__caixincallback1776017518675({
    "code": 0,
    "msg": "success",
    "data": {
        "uid": "...",
        "nickname": "...",
        "hasPassword": true,
        // ...
    }
})
```

### Response Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `10200` | No password set (use SMS login) |
| `10301` | Need to bind phone |
| `10401` | Invalid credentials |

## Session Cookies

After successful login, these cookies are set:

| Cookie | Description |
|--------|-------------|
| `SA_USER_auth` | Authentication token |
| `UID` | User ID |
| `SA_USER_NICK_NAME` | Display name |
| `SA_USER_USER_NAME` | Username |
| `SA_USER_UNIT` | Unit/organization |
| `SA_USER_DEVICE_TYPE` | Device type |
| `USER_LOGIN_CODE` | Login code |
| `SA_AUTH_TYPE` | Auth type |

## QR Code Login

### Flow

1. Generate QR code via `/api/ucenter/scan/v1/generateQRCode`
2. Set `LOGIN_QR_CODE` cookie with QR token
3. Poll `/api/ucenter/scan/v1/checkQRCodeStatus?qrCode={token}`
4. User scans QR with Caixin app
5. Poll returns status: `SCANED` → `CONFIRMED`
6. Extract `loginResult` from response

### Status Values

| Status | Description |
|--------|-------------|
| `NEW` | Waiting for scan |
| `SCANED` | Scanned, waiting for confirm |
| `CONFIRMED` | Login confirmed |
| `CANCELED` | User cancelled |
| `EXPIRED` | QR code expired |

## Tampermonkey Script

Install `userscripts/auto_relogin.js` as a Tampermonkey userscript for automatic re-login.

### Features

- Detects session kicks (code 600, or "其他设备" alert)
- Auto re-login when kicked
- Settings UI (click ⚙️ in Tampermonkey menu)
- Desktop notifications
- Periodic session monitoring

### Usage

1. Install the script in Tampermonkey
2. Click Tampermonkey icon → "⚙️ 设置"
3. Enter phone number and password
4. Enable "自动重新登录"
5. Click "保存"

### Menu Commands

| Command | Description |
|---------|-------------|
| ⚙️ 设置 | Open settings UI |
| 🔄 立即检查 | Check session status now |
| 🔑 立即登录 | Force re-login |

---

## Python Auth Script

Use `scripts/auth.py` to programmatically login and retrieve all auth cookies:

```bash
cd scripts
python3 auth.py
```

Configuration (edit the script):
```python
ACCOUNT = "19282708311"
PASSWORD = "Aa@19282708311"
AREA_CODE = "+86"
```

Output:
- Prints all auth cookies
- Saves to `auth_cookies.json`
- Provides cookie string for curl/requests

## Source Files

Client-side JavaScript:
- `https://file.caixin.com/pkg/cx-user-center/web/static/js/login.js`
- `https://file.caixin.com/pkg/cx-user-center/web/static/js/app.js`
- `https://file.caixin.com/pkg/cx-user-center/web/static/js/chunk-libs.js`

## Security Notes

- Password encryption uses ECB mode which is not semantically secure
- The encryption key is hardcoded in client-side JavaScript
- JSONP is used to bypass CORS (credentials in URL)
- `SA_USER_auth` token changes each login (session-based)
