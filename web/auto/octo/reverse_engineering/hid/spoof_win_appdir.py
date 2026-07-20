#!/usr/bin/env python3
"""CTF-style Windows HID spoof based on config.pyc get_windows_hid().

Octo calls, in order:
  1) pwsh  -NoProfile -NonInteractive -Command '(Get-CimInstance ... UUID)'
  2) powershell ... same
  3) wmic csproduct get uuid

CreateProcess searches the *application directory* before PATH, so we copy
Octo to a writable folder and drop powershell.exe / pwsh.exe shims beside
Octo Browser.exe.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
OVERRIDE = HERE / "hid_override.txt"
SHIM_SRC = HERE / "shim" / "powershell.exe"
SPOOFED_ROOT = Path.home() / "octo-re" / "OctoBrowser-spoofed"
STOCK_ROOT = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Octo Browser"
OCTO_DATA = Path(os.environ.get("APPDATA", "")) / "Octo Browser"


def ensure_shim_built() -> Path:
    if SHIM_SRC.exists():
        return SHIM_SRC
    # compile via spoof_win helper
    sys.path.insert(0, str(HERE))
    import spoof_win

    OVERRIDE.write_text("00000000-0000-4000-8000-0000000000AB\n", encoding="utf-8")
    spoof_win.install_shims(OVERRIDE.read_text().strip())
    if not SHIM_SRC.exists():
        raise SystemExit("Failed to build powershell.exe shim")
    return SHIM_SRC


def prepare_tree(fake_uuid: str, *, refresh: bool) -> Path:
    ensure_shim_built()
    OVERRIDE.write_text(fake_uuid + "\n", encoding="utf-8")
    if refresh and SPOOFED_ROOT.exists():
        shutil.rmtree(SPOOFED_ROOT)
    if not SPOOFED_ROOT.exists():
        print(f"[+] Copying {STOCK_ROOT} -> {SPOOFED_ROOT}")
        shutil.copytree(STOCK_ROOT, SPOOFED_ROOT)
    for name in ("powershell.exe", "pwsh.exe"):
        dst = SPOOFED_ROOT / name
        shutil.copy2(SHIM_SRC, dst)
        print(f"[+] App-dir shim: {dst}")
    # Override must sit beside the shim (CreateProcess app-dir layout)
    shutil.copy2(OVERRIDE, SPOOFED_ROOT / "hid_override.txt")
    print(f"[+] App-dir override: {SPOOFED_ROOT / 'hid_override.txt'}")
    # wmic.bat in app dir helps less (wmic is invoked as absolute often), but copy anyway
    wmic_bat = HERE / "shim" / "wmic.bat"
    if wmic_bat.exists():
        shutil.copy2(wmic_bat, SPOOFED_ROOT / "wmic.bat")
    return SPOOFED_ROOT / "Octo Browser.exe"


def kill_octo() -> None:
    subprocess.run(["taskkill", "/F", "/IM", "Octo Browser.exe"], capture_output=True)


def clear_storage() -> None:
    for name in ("local.data", "localpersist.data", "accounts_registry.data"):
        p = OCTO_DATA / name
        if p.exists():
            p.unlink()
            print(f"[+] cleared {name}")


def launch(exe: Path) -> None:
    env = os.environ.copy()
    env["OCTO_HID_OVERRIDE_FILE"] = str(OVERRIDE)
    # Put spoofed root first on PATH too (belt and suspenders)
    env["PATH"] = str(exe.parent) + os.pathsep + env.get("PATH", "")
    print(f"[+] Launching {exe}")
    subprocess.Popen([str(exe)], cwd=str(exe.parent), env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("hid", nargs="?", help="Override UUID")
    ap.add_argument("--refresh-copy", action="store_true", help="Re-copy Octo tree")
    ap.add_argument("--no-clear", action="store_true")
    ap.add_argument("--info", action="store_true")
    args = ap.parse_args()

    fake = (args.hid or "00000000-0000-4000-8000-0000000000AB").upper()
    if args.info:
        print("STOCK", STOCK_ROOT)
        print("SPOOFED", SPOOFED_ROOT, "exists=", SPOOFED_ROOT.exists())
        print("OVERRIDE", OVERRIDE.read_text().strip() if OVERRIDE.exists() else None)
        print("SHIM", SHIM_SRC, "exists=", SHIM_SRC.exists())
        return 0

    kill_octo()
    time.sleep(1)
    exe = prepare_tree(fake, refresh=args.refresh_copy)
    if not args.no_clear:
        clear_storage()
    launch(exe)
    print("[+] Override HID:", fake)
    print("[+] Watch debug.log for 'System query #2' then try decrypt with override UUID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
