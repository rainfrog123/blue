"""
Spam Enter into a Chromium/Electron window (e.g. Cursor) more reliably than a
raw PostMessage to the outer frame.

Why this exists:
  A Chromium window is a stack of nested HWNDs. GetForegroundWindow() returns the
  *outer frame* (class "Chrome_WidgetWin_1"), but the web UI receives input through
  an inner child window of class "Chrome_RenderWidgetHostHWND". Posting a key to
  the outer frame with lParam=0 is fragile and gets dropped the moment the window
  loses focus. This script:
    1. Finds the inner render-widget child window.
    2. Builds a correct WM_KEYDOWN/WM_KEYUP lParam (real scan code + transition bits).
    3. Posts to both the outer frame and the render-widget child each cycle.

  NOTE: Chromium still gates synthetic keys on focus/activation state, so even this
  may only work while the target window is focused. For truly focus-independent
  automation, drive Cursor via CDP / DOM injection instead. See the Obsidian note
  "Why Background Enter-Spam Fails on Cursor (Electron Focus)".

Usage:
  1. Run this script.
  2. Click the Cursor window you want to target within 3 seconds.
  3. Enter is pressed repeatedly until you press Ctrl+C.
"""

import time

import win32api
import win32con
import win32gui

RENDER_WIDGET_CLASS = "Chrome_RenderWidgetHostHWND"

# Bits 16-23 of lParam carry the OEM scan code; TranslateMessage needs it to
# generate the WM_CHAR that text inputs actually consume.
MAPVK_VK_TO_VSC = 0


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


def find_render_widget(top_hwnd: int) -> int | None:
    """Return the inner Chromium input-surface HWND, or None if not found."""
    hits: list[int] = []

    def _cb(h: int, _extra) -> bool:
        if win32gui.GetClassName(h) == RENDER_WIDGET_CLASS:
            hits.append(h)
        return True

    win32gui.EnumChildWindows(top_hwnd, _cb, None)
    return hits[0] if hits else None


def _build_lparam(vk_code: int, *, key_up: bool, extended: bool = False) -> int:
    """Pack a realistic lParam for a WM_KEYDOWN / WM_KEYUP message."""
    scan_code = win32api.MapVirtualKey(vk_code, MAPVK_VK_TO_VSC) & 0xFF

    lparam = 1                       # bits 0-15: repeat count
    lparam |= scan_code << 16        # bits 16-23: OEM scan code
    if extended:
        lparam |= 1 << 24            # bit 24: extended key flag
    if key_up:
        lparam |= 1 << 30            # bit 30: previous key state (was down)
        lparam |= 1 << 31            # bit 31: transition state (key up)
    return lparam


def _post_enter(hwnd: int, vk: int, down_lparam: int, up_lparam: int) -> None:
    win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, vk, down_lparam)
    win32api.PostMessage(hwnd, win32con.WM_KEYUP, vk, up_lparam)


def send_enter_loop(hwnd: int, interval: float = 0.05) -> None:
    render_widget = find_render_widget(hwnd)
    targets = [hwnd]
    if render_widget is not None:
        print(f"Found render widget child (HWND: {render_widget}).")
        if render_widget != hwnd:
            targets.append(render_widget)
    else:
        print("Warning: render-widget child not found; spamming outer frame only.")

    vk = win32con.VK_RETURN
    down_lparam = _build_lparam(vk, key_up=False)
    up_lparam = _build_lparam(vk, key_up=True)

    title = win32gui.GetWindowText(hwnd) or f"HWND {hwnd}"
    target_desc = ", ".join(str(t) for t in targets)
    print(f"Spamming Enter on '{title}' (HWNDs: {target_desc}). Press Ctrl+C in this terminal to stop.")

    try:
        while True:
            for target in targets:
                _post_enter(target, vk, down_lparam, up_lparam)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nScript stopped by user.")


def main() -> None:
    hwnd, _ = grab_foreground_window()
    if not hwnd:
        return
    send_enter_loop(hwnd)


if __name__ == "__main__":
    main()
