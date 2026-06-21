"""
Lock onto the active window, then spam Enter via PostMessage.

Usage:
  1. Run this script.
  2. Click the window you want to target within 3 seconds.
  3. Enter is pressed repeatedly until you press Ctrl+C.
"""

import time

import win32api
import win32con
import win32gui


def grab_foreground_window(countdown_seconds: float = 3.0) -> tuple[int, str] | tuple[None, None]:
    print("Quick! Click on the window you want to target.")
    print(f"Locking on in {countdown_seconds:.0f} seconds...")
    time.sleep(countdown_seconds)

    hwnd = win32gui.GetForegroundWindow()
    if not hwnd:
        print("Error: Could not get the foreground window.")
        return None, None

    window_title = win32gui.GetWindowText(hwnd)
    print(f"Target locked: {window_title} (HWND: {hwnd})")
    return hwnd, window_title


def send_enter_to_hwnd(hwnd: int) -> None:
    window_title = win32gui.GetWindowText(hwnd) or f"HWND {hwnd}"
    print(f"Spamming Enter on '{window_title}'. Press Ctrl+C in this terminal to stop.")

    try:
        while True:
            win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
            time.sleep(0.05)
            win32api.PostMessage(hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
    except KeyboardInterrupt:
        print("\nScript stopped by user.")


def main() -> None:
    hwnd, _ = grab_foreground_window()
    if not hwnd:
        return

    send_enter_to_hwnd(hwnd)


if __name__ == "__main__":
    main()
