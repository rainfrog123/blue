"""
Focus-independent "press Enter in Cursor" via the Chrome DevTools Protocol (CDP).

Why this exists
---------------
Win32 PostMessage / SendInput Enter-spam dies the moment Cursor loses focus,
because Chromium gates synthetic OS keys on the render widget's focus state and
drops them (see the Obsidian note "Why Background Enter-Spam Fails on Cursor
(Electron Focus)"). CDP sidesteps that entirely: we talk to Cursor's *own*
renderer over its debug socket and inject the action directly into the page's
DOM, so OS focus is irrelevant. Works while Cursor is in the background, behind
other windows, or on another virtual desktop.

Requirement
-----------
Cursor must be launched with a remote-debugging port, e.g.:

    cursor --remote-debugging-port=9222

If Cursor is already running without it, fully quit and relaunch with the flag.

Quick start
-----------
    # List CDP targets (find the workbench page):
    python send_enter_to_cursor_cdp.py --list

    # Dump candidate chat-input elements in a target (to pick a selector):
    python send_enter_to_cursor_cdp.py --inspect

    # Spam Enter into the agent input every 3s (DOM injection, default):
    python send_enter_to_cursor_cdp.py

    # One-shot:
    python send_enter_to_cursor_cdp.py --once

    # Use a custom selector if auto-detect misses your Cursor build:
    python send_enter_to_cursor_cdp.py --selector "div.aislash-editor-input"

    # Alternative: CDP synthetic key instead of DOM injection:
    python send_enter_to_cursor_cdp.py --mode key

Stop with Ctrl+C.

Dependencies: requests, websocket-client  (pip install requests websocket-client)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import requests
import websocket  # websocket-client


# --------------------------------------------------------------------------- #
# CDP plumbing                                                                 #
# --------------------------------------------------------------------------- #
class CdpError(RuntimeError):
    pass


def list_targets(port: int) -> list[dict[str, Any]]:
    """Return the CDP target list, or raise a friendly error."""
    url = f"http://127.0.0.1:{port}/json"
    try:
        resp = requests.get(url, timeout=4)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        raise CdpError(
            f"Could not reach Cursor's debug port at {url}.\n"
            "Launch Cursor with:  cursor --remote-debugging-port="
            f"{port}\n(Quit Cursor fully first if it is already open.)"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise CdpError(f"Failed to query {url}: {exc}") from exc
    return resp.json()


def pick_target(targets: list[dict[str, Any]], name_filter: str | None) -> dict[str, Any]:
    """Choose the workbench page target.

    Prefers type=='page' whose url/title matches `name_filter` (case-insensitive).
    Falls back to the first 'page' target, then the first target with a debugger url.
    """
    pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]

    if name_filter:
        needle = name_filter.lower()
        for t in pages:
            blob = (t.get("title", "") + " " + t.get("url", "")).lower()
            if needle in blob:
                return t

    # Cursor's main workbench window usually has a workbench URL.
    for t in pages:
        if "workbench" in (t.get("url", "").lower()):
            return t

    if pages:
        return pages[0]

    for t in targets:
        if t.get("webSocketDebuggerUrl"):
            return t

    raise CdpError("No CDP target with a webSocketDebuggerUrl was found.")


class CdpSession:
    """Minimal CDP websocket client (request/response by message id)."""

    def __init__(self, ws_url: str, timeout: float = 8.0) -> None:
        self._id = 0
        self._timeout = timeout
        self.ws = websocket.create_connection(ws_url, timeout=timeout, max_size=None)

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        msg_id = self._id
        self.ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
        # Read until we see our response id (skip async events).
        while True:
            raw = self.ws.recv()
            if not raw:
                continue
            data = json.loads(raw)
            if data.get("id") == msg_id:
                if "error" in data:
                    raise CdpError(f"{method} failed: {data['error']}")
                return data.get("result", {})

    def evaluate(self, expression: str) -> Any:
        result = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        if result.get("exceptionDetails"):
            raise CdpError(f"JS exception: {result['exceptionDetails']}")
        return result.get("result", {}).get("value")

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# DOM injection payloads                                                       #
# --------------------------------------------------------------------------- #
# Common selectors for the Cursor agent / chat input across builds. The script
# tries them in order; override with --selector if your build differs.
DEFAULT_SELECTORS = [
    'div.aislash-editor-input[contenteditable="true"]',
    ".aislash-editor-input",
    'div[contenteditable="true"].inputarea',
    "textarea.full-input-box",
    'textarea[data-testid="chat-input"]',
    'div[contenteditable="true"][role="textbox"]',
    'textarea[placeholder]',
]


def _js_string_array(items: list[str]) -> str:
    return "[" + ",".join(json.dumps(s) for s in items) + "]"


def build_enter_js(selectors: list[str]) -> str:
    """JS that finds the chat input and dispatches a full Enter key sequence.

    Returns a short status string so the Python side can log what happened.
    """
    sel_arr = _js_string_array(selectors)
    return (
        "(() => {"
        f"  const selectors = {sel_arr};"
        "  const visible = (el) => {"
        "    if (!el) return false;"
        "    const r = el.getBoundingClientRect();"
        "    return r.width > 0 && r.height > 0;"
        "  };"
        "  let el = null;"
        "  for (const s of selectors) {"
        "    const found = Array.from(document.querySelectorAll(s)).filter(visible);"
        "    if (found.length) { el = found[found.length - 1]; break; }"
        "  }"
        "  if (!el) {"
        "    const a = document.activeElement;"
        "    if (a && (a.isContentEditable || a.tagName === 'TEXTAREA')) el = a;"
        "  }"
        "  if (!el) return 'no-input-found';"
        "  el.focus();"
        "  const opts = {key:'Enter', code:'Enter', keyCode:13, which:13, bubbles:true, cancelable:true, composed:true};"
        "  el.dispatchEvent(new KeyboardEvent('keydown', opts));"
        "  el.dispatchEvent(new KeyboardEvent('keypress', opts));"
        "  el.dispatchEvent(new KeyboardEvent('keyup', opts));"
        "  return 'enter-dispatched:' + (el.tagName.toLowerCase()) + (el.className ? '.' + String(el.className).split(' ')[0] : '');"
        "})()"
    )


def build_inspect_js() -> str:
    """JS that returns a summary of candidate editable elements for selector discovery."""
    return (
        "(() => {"
        "  const els = Array.from(document.querySelectorAll('textarea, [contenteditable=\"true\"], [role=\"textbox\"]'));"
        "  return els.slice(0, 25).map((el) => {"
        "    const r = el.getBoundingClientRect();"
        "    return {"
        "      tag: el.tagName.toLowerCase(),"
        "      cls: el.className || '',"
        "      id: el.id || '',"
        "      placeholder: el.getAttribute('placeholder') || '',"
        "      aria: el.getAttribute('aria-label') || '',"
        "      visible: r.width > 0 && r.height > 0,"
        "    };"
        "  });"
        "})()"
    )


# --------------------------------------------------------------------------- #
# Main actions                                                                 #
# --------------------------------------------------------------------------- #
def do_list(port: int) -> None:
    targets = list_targets(port)
    if not targets:
        print("No CDP targets found.")
        return
    print(f"CDP targets on port {port}:\n")
    for t in targets:
        print(f"  [{t.get('type')}] {t.get('title', '')!r}")
        print(f"      url: {t.get('url', '')[:100]}")
        print(f"      ws : {'yes' if t.get('webSocketDebuggerUrl') else 'no'}\n")


def do_inspect(session: CdpSession) -> None:
    session.call("Runtime.enable")
    rows = session.evaluate(build_inspect_js())
    if not rows:
        print("No textarea / contenteditable / textbox elements found in this target.")
        return
    print("Candidate input elements (newest/last is usually the active chat box):\n")
    for r in rows:
        vis = "visible" if r.get("visible") else "hidden "
        print(f"  [{vis}] <{r['tag']}> cls={r['cls']!r} id={r['id']!r} "
              f"ph={r['placeholder']!r} aria={r['aria']!r}")


def send_enter_key_cdp(session: CdpSession) -> None:
    """Alternative: synthetic key via CDP Input domain (selector-independent)."""
    base = {"key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13}
    session.call("Input.dispatchKeyEvent", {"type": "rawKeyDown", **base})
    session.call("Input.dispatchKeyEvent", {"type": "char", "text": "\r", **base})
    session.call("Input.dispatchKeyEvent", {"type": "keyUp", **base})


def run_loop(session: CdpSession, *, mode: str, selectors: list[str],
             interval: float, once: bool) -> None:
    session.call("Runtime.enable")
    enter_js = build_enter_js(selectors)

    action = "DOM injection" if mode == "dom" else "CDP synthetic key"
    if once:
        print(f"Sending one Enter via {action}...")
    else:
        print(f"Spamming Enter via {action} every {interval}s. Press Ctrl+C to stop.")

    try:
        while True:
            if mode == "dom":
                status = session.evaluate(enter_js)
                stamp = time.strftime("%H:%M:%S")
                print(f"[{stamp}] {status}")
                if status == "no-input-found":
                    print("        (No chat input matched. Run --inspect to find the right "
                          "--selector, or make sure the agent chat is open.)")
            else:
                send_enter_key_cdp(session)
                print(f"[{time.strftime('%H:%M:%S')}] key dispatched")

            if once:
                return
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped by user.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Focus-independent Enter sender for Cursor via CDP.")
    parser.add_argument("--port", type=int, default=9222, help="Remote debugging port (default 9222).")
    parser.add_argument("--interval", type=float, default=3.0, help="Seconds between presses (default 3).")
    parser.add_argument("--mode", choices=["dom", "key"], default="dom",
                        help="dom = DOM injection (default, most focus-proof); key = CDP synthetic key.")
    parser.add_argument("--selector", action="append", default=None,
                        help="Override chat-input CSS selector (repeatable). Defaults to a built-in list.")
    parser.add_argument("--target", default=None,
                        help="Substring to match the CDP target title/url (default: auto-detect workbench).")
    parser.add_argument("--once", action="store_true", help="Send a single Enter and exit.")
    parser.add_argument("--list", action="store_true", help="List CDP targets and exit.")
    parser.add_argument("--inspect", action="store_true",
                        help="Dump candidate input elements in the target and exit.")
    args = parser.parse_args()

    try:
        if args.list:
            do_list(args.port)
            return 0

        targets = list_targets(args.port)
        target = pick_target(targets, args.target)
        print(f"Target: [{target.get('type')}] {target.get('title', '')!r}")

        session = CdpSession(target["webSocketDebuggerUrl"])
        try:
            if args.inspect:
                do_inspect(session)
                return 0

            selectors = args.selector if args.selector else DEFAULT_SELECTORS
            run_loop(session, mode=args.mode, selectors=selectors,
                     interval=args.interval, once=args.once)
        finally:
            session.close()
        return 0
    except CdpError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
