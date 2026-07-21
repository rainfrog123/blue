# How Windows HID spoof works (`spoof_win_appdir.py`)

Teach-me note for the app-dir shim approach. Longer Obsidian version: `Daily Notes/Octo HID Spoof Explained.md`.

## One sentence

Octo on Windows gets HID by **spawning** `pwsh` / `powershell` / `wmic` and reading the printed UUID. We place a **fake `pwsh.exe`/`powershell.exe` next to a copied Octo exe** so `CreateProcess` runs our shim first; the shim prints `hid_override.txt`.

## Why not edit the real UUID?

Windows product UUID lives in SMBIOS (firmware). Guests can’t usefully rewrite it like Linux `/etc/machine-id`. Spoof the **query path** instead.

## What Octo runs (`config.pyc` → `get_windows_hid`)

1. `pwsh -NoProfile -NonInteractive -Command '(Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)'`
2. same with `powershell`
3. `wmic csproduct get uuid`

`debug.log` lines `System query #1/#2` are those attempts.

## Why app-dir (not only PATH)?

`CreateProcess` search order (simplified): **application directory → cwd → system dirs → PATH**.  
Shims beside `Octo Browser.exe` win reliably. That’s what `spoof_win_appdir.py` sets up under `~\octo-re\OctoBrowser-spoofed\`.

## Script steps

1. Compile shim (`shim_powershell.cs` via `spoof_win.py` / `csc`) if needed  
2. Copy stock Octo → spoofed tree  
3. Drop `pwsh.exe`, `powershell.exe`, `hid_override.txt` next to the exe  
4. Clear AppData storage (old ciphertext is bound to old HID)  
5. Launch spoofed exe  

Shim: if args look like a product-UUID query → print override; else call real PowerShell.

## Proof

- Log: query #1 succeeds in ~100ms with shim (real WMI was seconds)  
- `localpersist.data` decrypts with **fake** HID only  

## Launch cheat sheet

| Start this | HID |
| --- | --- |
| `OctoBrowser-spoofed\Octo Browser.exe` / `spoof_win_appdir.py` | Fake from `hid_override.txt` |
| `Program Files\Octo Browser` / Start Menu | Real SMBIOS |

```powershell
python reverse_engineering/hid/spoof_win_appdir.py
```
