"""
Grab the HWND of whatever window is active after a short countdown.

Usage:
  1. Run this script.
  2. Click the window you want to target.
  3. After 3 seconds, the script locks onto that window's handle.
"""

import time

import win32gui


def main() -> None:
    print("Quick! Click on the window you want to target.")
    print("Locking on in 3 seconds...")
    time.sleep(3)

    # Grabs the HWND of whatever window is currently in the foreground
    hwnd = win32gui.GetForegroundWindow()
    window_title = win32gui.GetWindowText(hwnd)

    print(f"Target Locked: {window_title} (HWND: {hwnd})")


if __name__ == "__main__":
    main()
