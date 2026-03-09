# Ghidra Reverse Engineering Guides

Step-by-step guides for discovering OctoBrowser's HID fingerprinting and storage encryption using Ghidra.

## Prerequisites

- Ghidra (`/opt/ghidra`)
- OctoBrowser AppImage extracted (pyinstxtractor)
- Python 3.x, `cryptography`, pycdc/uncompyle6
- VNC or X11 display for GUI

---

# Part 1: HID Discovery

How Ghidra was used to discover OctoBrowser's hardware fingerprinting mechanism.

## 1.1 Extract and Identify Target

```bash
chmod +x OctoBrowser.AppImage
./OctoBrowser.AppImage --appimage-extract
# Or: python3 pyinstxtractor.py OctoBrowser.AppImage

# Key target: libdbus-1.so.3 (reads /etc/machine-id)
strings OctoBrowser.AppImage_extracted/*.so* | grep -i machine
# Reveals: machine-id, /etc/machine-id, dbus_get_local_machine_id
```

## 1.2 Ghidra Analysis (libdbus)

1. **Search → For Strings** → `machine`
2. **Symbol Table** → filter `machine`
3. Key symbols: `dbus_get_local_machine_id`, `_dbus_read_local_machine_uuid`, `_dbus_get_local_machine_uuid_encoded`
4. Decompile `_dbus_read_local_machine_uuid` — reads `/etc/machine-id`

## 1.3 Python Bytecode (config.pyc)

```bash
pycdc PYZ.pyz_extracted/config.pyc
# Reveals: SECRET_KEY = "TeNtAcLeShErE___"
# Cross-platform HID: Linux (/etc/machine-id), macOS (ioreg), Windows (PowerShell)
```

## 1.4 Key Findings

| Component | Value |
|-----------|-------|
| HID Source (Linux) | `/etc/machine-id` |
| Format | 32 hex characters |
| Usage | Encryption key + license binding |

---

# Part 2: Storage Decryption

How to discover encryption parameters for `local.data` and `localpersist.data`.

## 2.1 Target Files

| File | Contents |
|------|----------|
| `config.pyc` | SECRET_KEY, HID retrieval |
| `octo_crypto/encryption/ciphers/fernet.pyc` | PBKDF2 iterations |
| `octo/helpers/encryption.pyc` | password_hash() |
| `octo/helpers/storage.pyc` | Storage class |

## 2.2 Quick Strings Search

```bash
strings config.pyc | grep -i "secret\|tentacle"
# TeNtAcLeShErE___

strings fernet.pyc | grep -i "pbkdf2\|iterations"
```

## 2.3 Python Marshal (Extract Constants)

```python
import marshal
with open('fernet.pyc', 'rb') as f:
    f.read(16)  # Skip header
    code = marshal.load(f)
# Find nested int > 10000 → 100000 (iterations)
```

## 2.4 Encryption Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Algorithm | Fernet (AES-128-CBC + HMAC-SHA256) | fernet.pyc |
| KDF | PBKDF2-HMAC-SHA256 | fernet.pyc |
| Iterations | 100,000 | fernet.pyc |
| SECRET_KEY | `TeNtAcLeShErE___` | config.pyc |
| Password | Machine HID | storage.pyc |
| Salt | First 16 bytes of HID (padded) | encryptor.pyc |

## 2.5 Decryption Formula

```
Password  = /etc/machine-id (Linux)
Salt      = Password[:16].ljust(16, '\x00')
Key       = PBKDF2(SHA256, Password, Salt, iterations=100000, length=32)
Fernet_Key = base64_urlsafe_encode(Key)
Plaintext = Fernet(Fernet_Key).decrypt(ciphertext)
Content   = json.loads(Plaintext)
```

## 2.6 Working Tools

| File | Purpose |
|------|---------|
| `../storage_decryption/octo_storage_decryptor.py` | Decrypt storage |
| `ghidra_encryption_analyzer.py` | Ghidra analysis script |

---

# Ghidra Tips

| Key | Action |
|-----|--------|
| `G` | Go to address |
| `L` | Rename |
| `S` | Search strings |
| `Ctrl+Shift+E` | Show references |

**Headless:** `analyzeHeadless <dir> <project> -import <binary> -postScript script.py`
