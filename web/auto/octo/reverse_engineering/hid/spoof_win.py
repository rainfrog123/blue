#!/usr/bin/env python3
"""
OctoBrowser HID Spoofing Tool — Windows

SMBIOS UUID (Win32_ComputerSystemProduct) cannot be changed from inside the
guest. Octo on Windows obtains HID via PowerShell / WMIC subprocesses
(see docs/octo_hid.md), so this tool:

  1. Writes an override UUID
  2. Installs PATH shims (powershell.bat / wmic.bat) that return the override
  3. Backs up + clears Octo encrypted storage
  4. Can launch Octo with the shim directory prepended to PATH

Usage:
    python spoof_win.py --info
    python spoof_win.py                 # random UUID (dashed)
    python spoof_win.py <uuid>          # specific UUID
    python spoof_win.py --restore
    python spoof_win.py --launch        # start Octo with shim PATH
    python spoof_win.py --test-shim     # verify shim returns override
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

TOOL_DIR = Path(__file__).resolve().parent
OVERRIDE_FILE = TOOL_DIR / "hid_override.txt"
BACKUP_HID_FILE = TOOL_DIR / "hid_real_backup.txt"
SHIM_DIR = TOOL_DIR / "shim"
STORAGE_BACKUP_DIR = TOOL_DIR / "storage_backup"

OCTO_DIR = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "Octo Browser"
OCTO_EXE_CANDIDATES = [
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Octo Browser" / "Octo Browser.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Octo Browser" / "Octo Browser.exe",
]

OCTO_STORAGE_FILES = [
    "local.data",
    "localpersist.data",
    "accounts_registry.data",
]

UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)


class C:
    R = "\033[0;31m"
    G = "\033[0;32m"
    Y = "\033[1;33m"
    B = "\033[0;34m"
    C = "\033[0;36m"
    N = "\033[0m"


def ok(msg: str) -> None:
    print(f"{C.G}[+]{C.N} {msg}")


def warn(msg: str) -> None:
    print(f"{C.Y}[!]{C.N} {msg}")


def err(msg: str) -> None:
    print(f"{C.R}[-]{C.N} {msg}")


def header() -> None:
    print(f"{C.C}{'=' * 56}")
    print("  OctoBrowser HID Spoof — Windows")
    print(f"{'=' * 56}{C.N}")


def get_real_smbios_uuid() -> Optional[str]:
    """Read SMBIOS UUID via absolute powershell.exe (ignores PATH shims)."""
    try:
        real_ps = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        if not real_ps.exists():
            err(f"Real powershell not found: {real_ps}")
            return None
        r = subprocess.run(
            [
                str(real_ps),
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        val = (r.stdout or "").strip().splitlines()
        return val[-1].strip() if val else None
    except Exception as e:
        err(f"Failed to read SMBIOS UUID: {e}")
        return None


def get_override() -> Optional[str]:
    if OVERRIDE_FILE.exists():
        return OVERRIDE_FILE.read_text(encoding="utf-8").strip() or None
    return None


def validate_uuid(value: str) -> bool:
    return bool(UUID_RE.match(value))


def normalize_uuid(value: str) -> str:
    raw = value.strip().replace("{", "").replace("}", "")
    if len(raw) == 32 and all(c in "0123456789abcdefABCDEF" for c in raw):
        raw = f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
    return raw.upper()


def find_octo_exe() -> Optional[Path]:
    for p in OCTO_EXE_CANDIDATES:
        if p and p.exists():
            return p
    return None


def kill_octo() -> None:
    subprocess.run(
        ["taskkill", "/F", "/IM", "Octo Browser.exe"],
        capture_output=True,
        check=False,
    )
    time.sleep(1)
    ok("Stopped Octo Browser (if it was running)")


def backup_storage() -> None:
    if not OCTO_DIR.exists():
        warn(f"Octo dir missing: {OCTO_DIR}")
        return
    STORAGE_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    for name in OCTO_STORAGE_FILES:
        src = OCTO_DIR / name
        if src.exists():
            dst = STORAGE_BACKUP_DIR / name
            shutil.copy2(src, dst)
            ok(f"Backed up {name} -> {dst}")


def clear_storage() -> None:
    if not OCTO_DIR.exists():
        warn(f"Octo dir missing: {OCTO_DIR}")
        return
    for name in OCTO_STORAGE_FILES:
        path = OCTO_DIR / name
        if path.exists():
            path.unlink()
            ok(f"Removed {name}")


def restore_storage() -> None:
    if not STORAGE_BACKUP_DIR.exists():
        err(f"No storage backup at {STORAGE_BACKUP_DIR}")
        return
    OCTO_DIR.mkdir(parents=True, exist_ok=True)
    for src in STORAGE_BACKUP_DIR.iterdir():
        if src.is_file():
            shutil.copy2(src, OCTO_DIR / src.name)
            ok(f"Restored {src.name}")


WMIC_SHIM = r'''@echo off
REM WMIC fallback shim — UUID queries only. Avoids %* paren issues via temp file.
setlocal EnableExtensions
set "OVERRIDE_FILE=__OVERRIDE_FILE__"
set "REAL_WMIC=%SystemRoot%\System32\wbem\WMIC.exe"
set "TMPARGS=%TEMP%\octo_wmic_args_%RANDOM%.txt"
echo %*>"%TMPARGS%" 2>nul
findstr /I /C:"csproduct" "%TMPARGS%" >nul
set "HIT=%ERRORLEVEL%"
del "%TMPARGS%" >nul 2>&1
if "%HIT%"=="0" goto :fake
if exist "%REAL_WMIC%" (
  "%REAL_WMIC%" %*
  exit /b %ERRORLEVEL%
)
exit /b 1

:fake
if not exist "%OVERRIDE_FILE%" (
  if exist "%REAL_WMIC%" "%REAL_WMIC%" %*
  exit /b %ERRORLEVEL%
)
echo UUID
type "%OVERRIDE_FILE%"
exit /b 0
'''


def _compile_powershell_shim() -> Path:
    """Compile shim_powershell.cs -> shim/powershell.exe via .NET Framework csc."""
    cs_src = TOOL_DIR / "shim_powershell.cs"
    if not cs_src.exists():
        raise RuntimeError(f"Missing {cs_src}")

    out_exe = SHIM_DIR / "powershell.exe"
    SHIM_DIR.mkdir(parents=True, exist_ok=True)

    frameworks = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64"
    csc = None
    if frameworks.exists():
        for v in sorted(frameworks.glob("v4.*"), reverse=True):
            cand = v / "csc.exe"
            if cand.exists():
                csc = cand
                break
    if csc is None:
        raise RuntimeError("csc.exe not found under Microsoft.NET\\Framework64")

    # Remove stale bat shim that can confuse debugging
    bat = SHIM_DIR / "powershell.bat"
    if bat.exists():
        bat.unlink()

    r = subprocess.run(
        [str(csc), "/nologo", "/optimize+", f"/out:{out_exe}", str(cs_src)],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0 or not out_exe.exists():
        raise RuntimeError(f"csc failed ({r.returncode}): {r.stdout}\n{r.stderr}")
    return out_exe


def install_shims(override_uuid: str) -> None:
    SHIM_DIR.mkdir(parents=True, exist_ok=True)
    OVERRIDE_FILE.write_text(override_uuid + "\n", encoding="utf-8")
    exe = _compile_powershell_shim()
    ok(f"Compiled PowerShell shim: {exe}")

    override_path = str(OVERRIDE_FILE).replace("/", "\\")
    wmic = WMIC_SHIM.replace("__OVERRIDE_FILE__", override_path)
    (SHIM_DIR / "wmic.bat").write_text(wmic, encoding="utf-8")
    ok(f"Installed shims in {SHIM_DIR}")

def uninstall_shims() -> None:
    if SHIM_DIR.exists():
        shutil.rmtree(SHIM_DIR)
        ok(f"Removed shim dir {SHIM_DIR}")
    if OVERRIDE_FILE.exists():
        OVERRIDE_FILE.unlink()
        ok("Removed hid_override.txt")


def shim_env() -> dict:
    env = os.environ.copy()
    env["PATH"] = str(SHIM_DIR) + os.pathsep + env.get("PATH", "")
    return env


def test_shim() -> int:
    shim_exe = SHIM_DIR / "powershell.exe"
    if not shim_exe.exists():
        err("Shims not installed — run a spoof first")
        return 1
    override = get_override()
    # Important: on Windows, subprocess does not use env['PATH'] to resolve the
    # executable name — always invoke the shim by absolute path for the test.
    r = subprocess.run(
        [
            str(shim_exe),
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    got = (r.stdout or "").strip().splitlines()
    got_val = got[-1].strip() if got else ""
    print(f"  Override file: {override}")
    print(f"  Shim returned: {got_val}")
    real = get_real_smbios_uuid()
    print(f"  Real SMBIOS:   {real}")
    if override and got_val.upper() == override.upper():
        ok("Shim works (absolute path)")
        ok("Octo launched via --launch inherits shim PATH so its child lookups resolve the shim exe")
        return 0
    err("Shim did not return override UUID")
    if r.stderr:
        print(r.stderr)
    return 1


def show_info() -> None:
    real = get_real_smbios_uuid()
    override = get_override()
    print(f"\n{C.B}Current status{C.N}")
    print(f"  Real SMBIOS UUID: {real or 'unknown'}")
    print(f"  Override file:    {OVERRIDE_FILE}")
    print(f"  Override UUID:    {override or '(none)'}")
    print(f"  Shim dir:         {SHIM_DIR} {'(present)' if SHIM_DIR.exists() else '(absent)'}")
    print(f"  Octo data dir:    {OCTO_DIR}")
    exe = find_octo_exe()
    print(f"  Octo exe:         {exe or 'not found'}")
    if OCTO_DIR.exists():
        present = []
        for name in OCTO_STORAGE_FILES:
            p = OCTO_DIR / name
            if p.exists():
                present.append(f"{name} ({p.stat().st_size} B)")
        print(f"  Storage files:    {', '.join(present) if present else '(none)'}")
    if STORAGE_BACKUP_DIR.exists():
        print(f"  Storage backup:   {STORAGE_BACKUP_DIR}")
    print()
    warn("SMBIOS UUID itself is not modified — spoof is via PATH shims for PowerShell/WMIC.")


def launch_octo() -> int:
    exe = find_octo_exe()
    if not exe:
        err("Octo Browser.exe not found")
        return 1
    if not get_override() or not SHIM_DIR.exists():
        err("No active spoof — run spoof first")
        return 1
    ok(f"Launching {exe} with shim PATH")
    subprocess.Popen([str(exe)], env=shim_env(), cwd=str(exe.parent))
    return 0


def do_spoof(new_hid: str, *, yes: bool, do_launch: bool) -> int:
    real = get_real_smbios_uuid()
    show_info()
    print(f"{C.Y}This will:{C.N}")
    print(f"  1. Remember real SMBIOS UUID: {real}")
    print(f"  2. Set override HID: {new_hid}")
    print(f"  3. Install PATH shims under {SHIM_DIR}")
    print("  4. Stop Octo Browser")
    print("  5. Backup + clear encrypted storage (forces re-login)")
    if do_launch:
        print("  6. Launch Octo with shim PATH")
    print()
    if not yes:
        ans = input("Continue? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            warn("Aborted.")
            return 0

    if real:
        BACKUP_HID_FILE.write_text(real + "\n", encoding="utf-8")
        ok(f"Saved real UUID to {BACKUP_HID_FILE}")

    OVERRIDE_FILE.write_text(new_hid + "\n", encoding="utf-8")
    install_shims(new_hid)
    kill_octo()
    backup_storage()
    clear_storage()

    print()
    print(f"{C.G}{'=' * 56}")
    print("  Windows HID spoof ready")
    print(f"{'=' * 56}{C.N}")
    print(f"  Real SMBIOS: {real}")
    print(f"  Override:    {new_hid}")
    print()
    print("  Next:")
    print(f"    python {Path(__file__).name} --test-shim")
    print(f"    python {Path(__file__).name} --launch")
    print(f"    python {Path(__file__).name} --restore")
    print()

    rc = test_shim()
    if do_launch and rc == 0:
        return launch_octo()
    return rc


def do_restore(*, yes: bool, restore_files: bool) -> int:
    show_info()
    if not yes:
        ans = input("Remove shims/override and optionally restore storage? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            warn("Aborted.")
            return 0
    kill_octo()
    uninstall_shims()
    if restore_files:
        restore_storage()
    else:
        warn("Storage not restored (pass --restore-storage to copy backup back)")
    ok("Restore complete — Octo will see real SMBIOS UUID again")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="OctoBrowser HID spoof (Windows PATH-shim)")
    parser.add_argument("hid", nargs="?", help="Override UUID (dashed or 32-hex)")
    parser.add_argument("--info", "-i", action="store_true")
    parser.add_argument("--restore", "-r", action="store_true", help="Remove shims/override")
    parser.add_argument("--restore-storage", action="store_true", help="Also restore storage backup")
    parser.add_argument("--launch", action="store_true", help="Launch Octo with shim PATH")
    parser.add_argument("--test-shim", action="store_true")
    parser.add_argument("--yes", "-y", action="store_true")
    args = parser.parse_args()

    header()

    if args.info:
        show_info()
        return 0
    if args.test_shim:
        return test_shim()
    if args.launch and not args.hid and not args.restore:
        return launch_octo()
    if args.restore:
        return do_restore(yes=args.yes, restore_files=args.restore_storage)

    if args.hid:
        new_hid = normalize_uuid(args.hid)
        if not validate_uuid(new_hid):
            err("Invalid UUID. Example: 00000000-0000-0000-0000-000000000001")
            return 1
    else:
        new_hid = str(uuid.uuid4()).upper()

    return do_spoof(new_hid, yes=args.yes, do_launch=args.launch)


if __name__ == "__main__":
    sys.exit(main())
