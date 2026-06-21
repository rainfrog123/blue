#!/usr/bin/env python3
"""Minimal raw-CDP driver for the Cursor workbench renderer.

Requires: Cursor launched with
    --remote-debugging-port=9222 --remote-allow-origins=*

Usage:
    python cdp.py --list                 # list page targets + which has the chat editor
    python cdp.py --eval "1+1"           # evaluate JS in the workbench page, print result + console
    python cdp.py --file script.js       # evaluate a JS file in the workbench page
    python cdp.py --eval "..." --all     # run against EVERY workbench page (multi-window)

Notes:
  - Auto-picks the page containing `.tiptap.ProseMirror` (the chat composer).
  - Captures console.log/warn/error emitted during evaluation.
  - Wrap async work in an IIFE that RETURNS a value to get it back cleanly, e.g.
        (async()=>{ ...; return {ok:true}; })()
"""
import argparse, json, os, random, sys, time, urllib.request
import websocket  # pip install websocket-client

CDP = "http://127.0.0.1:9222"


def http_json(path):
    with urllib.request.urlopen(CDP + path, timeout=5) as r:
        return json.load(r)


def page_targets():
    return [t for t in http_json("/json/list") if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]


class Session:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=180, suppress_origin=True, max_size=None)
        self._id = 0

    def _next(self):
        self._id += 1
        return self._id

    def call(self, method, params=None, collect_console=False):
        mid = self._next()
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        console = []
        while True:
            msg = json.loads(self.ws.recv())
            if collect_console and msg.get("method") == "Runtime.consoleAPICalled":
                p = msg["params"]
                args = " ".join(_render(a) for a in p.get("args", []))
                console.append(f"[{p.get('type')}] {args}")
            if msg.get("id") == mid:
                return msg, console

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def _render(remote_obj):
    if "value" in remote_obj:
        v = remote_obj["value"]
        return v if isinstance(v, str) else json.dumps(v)
    return remote_obj.get("description", remote_obj.get("type", "?"))


def evaluate(ws_url, expr, await_promise=True, want_console=True):
    s = Session(ws_url)
    try:
        s.call("Runtime.enable")
        resp, console = s.call("Runtime.evaluate", {
            "expression": expr,
            "returnByValue": True,
            "awaitPromise": await_promise,
            "userGesture": True,
        }, collect_console=want_console)
        return resp.get("result", {}), console
    finally:
        s.close()


_KEYS = {
    "enter": ("Enter", "Enter", 13),
    "tab": ("Tab", "Tab", 9),
    "escape": ("Escape", "Escape", 27),
    "arrowright": ("ArrowRight", "ArrowRight", 39),
    "arrowleft": ("ArrowLeft", "ArrowLeft", 37),
    "arrowdown": ("ArrowDown", "ArrowDown", 40),
    "arrowup": ("ArrowUp", "ArrowUp", 38),
    "space": (" ", "Space", 32),
    "backspace": ("Backspace", "Backspace", 8),
}
_MODS = {"alt": 1, "ctrl": 2, "control": 2, "meta": 4, "cmd": 4, "command": 4, "shift": 8}


def _keyinfo(name):
    n = name.lower()
    if n in _KEYS:
        return _KEYS[n]
    if len(name) == 1:
        ch = name
        return (ch, f"Key{ch.upper()}" if ch.isalpha() else ch, ord(ch.upper()))
    raise ValueError(f"unknown key: {name}")


def send_chord(ws_url, chord, focus_eval=None):
    """Send a TRUSTED key chord like 'Control+d' via Input.dispatchKeyEvent."""
    s = Session(ws_url)
    try:
        s.call("Runtime.enable")
        if focus_eval:
            s.call("Runtime.evaluate", {"expression": focus_eval, "awaitPromise": True, "userGesture": True})
        parts = chord.split("+")
        mods = 0
        for m in parts[:-1]:
            mods |= _MODS[m.lower()]
        key, code, vk = _keyinfo(parts[-1])

        def k(kind, key, code, vk, mods):
            s.call("Input.dispatchKeyEvent", {
                "type": kind, "key": key, "code": code,
                "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk, "modifiers": mods,
            })

        if mods & 2:
            k("rawKeyDown", "Control", "ControlLeft", 17, 2)
        if mods & 8:
            k("rawKeyDown", "Shift", "ShiftLeft", 16, mods)
        k("rawKeyDown", key, code, vk, mods)
        k("keyUp", key, code, vk, mods)
        if mods & 8:
            k("keyUp", "Shift", "ShiftLeft", 16, mods & ~8)
        if mods & 2:
            k("keyUp", "Control", "ControlLeft", 17, 0)
    finally:
        s.close()


def click_at(ws_url, x, y):
    """Trusted left-click at viewport coords (real mouse events, not DOM .click()).

    A real pointer press dismisses open popovers (e.g. the model picker) via the
    app's outside-click handling, and focuses whatever is under the cursor.
    """
    s = Session(ws_url)
    try:
        s.call("Runtime.enable")
        s.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        s.call("Input.dispatchMouseEvent", {
            "type": "mousePressed", "x": x, "y": y,
            "button": "left", "buttons": 1, "clickCount": 1,
        })
        s.call("Input.dispatchMouseEvent", {
            "type": "mouseReleased", "x": x, "y": y,
            "button": "left", "buttons": 0, "clickCount": 1,
        })
    finally:
        s.close()


def hold_key(ws_url, key_name, duration=None, interval=0.12, jitter=0.35,
             focus_eval=None, refocus_every=8, stop_eval=None, poll_every=3, max_secs=None):
    """Press and HOLD a key: one keyDown, then autoRepeat keyDowns at a (jittered,
    human-like) cadence, then a single keyUp.

    Stop conditions (whichever comes first):
      - `duration` seconds elapsed (if given)
      - `max_secs` seconds elapsed (safety cap; None/0 = no cap)
      - `stop_eval` JS expression evaluates truthy (polled every `poll_every` repeats)
    If only `stop_eval` is given (no duration), holds indefinitely until it is truthy.

    Stays in one CDP session so focus never leaves the target between repeats;
    re-runs `focus_eval` every `refocus_every` repeats to keep the input focused.
    """
    s = Session(ws_url)
    try:
        s.call("Runtime.enable")

        def focus():
            if focus_eval:
                s.call("Runtime.evaluate", {
                    "expression": focus_eval, "awaitPromise": True, "userGesture": True,
                })

        def stop_now():
            if not stop_eval:
                return False
            resp, _ = s.call("Runtime.evaluate", {
                "expression": stop_eval, "returnByValue": True, "awaitPromise": True,
            })
            return bool(resp.get("result", {}).get("result", {}).get("value"))

        key, code, vk = _keyinfo(key_name)

        def k(kind, auto=False):
            s.call("Input.dispatchKeyEvent", {
                "type": kind, "key": key, "code": code,
                "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk,
                "autoRepeat": auto,
            })

        focus()
        k("rawKeyDown")
        presses = 1
        start = time.time()
        deadline = start + duration if duration else None
        while True:
            delay = max(0.03, random.gauss(interval, interval * jitter)) if jitter else interval
            time.sleep(delay)
            k("rawKeyDown", auto=True)
            presses += 1
            if refocus_every and presses % refocus_every == 0:
                focus()
            if stop_eval and presses % poll_every == 0 and stop_now():
                break
            if deadline and time.time() > deadline:
                break
            if max_secs and (time.time() - start) > max_secs:
                break
        k("keyUp")
        return presses
    finally:
        s.close()


def has_editor(ws_url):
    try:
        res, _ = evaluate(ws_url, "!!document.querySelector('.tiptap.ProseMirror')",
                          await_promise=False, want_console=False)
        return bool(res.get("result", {}).get("value"))
    except Exception:
        return False


def find_workbench():
    for t in page_targets():
        if has_editor(t["webSocketDebuggerUrl"]):
            return t["webSocketDebuggerUrl"], t
    return None, None


def all_workbench():
    return [t for t in page_targets() if has_editor(t["webSocketDebuggerUrl"])]


def js_bundle(*names):
    here = os.path.dirname(os.path.abspath(__file__))
    return "\n".join(open(os.path.join(here, n), encoding="utf-8").read() for n in names)


def print_result(res, console):
    for line in console:
        print("CONSOLE", line)
    r = res.get("result", {})
    exc = res.get("exceptionDetails")
    if exc:
        print("EXCEPTION", json.dumps(exc.get("exception", exc), indent=2)[:2000])
    else:
        print("RESULT", _render(r))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--status", action="store_true", help="show tiled chat state (tiles, models, planning, generating)")
    ap.add_argument("--watch-planning", action="store_true", help="poll until 'Planning next moves' appears")
    ap.add_argument("--wait", type=float, default=15.0, help="seconds to poll for --watch-planning (default 15)")
    ap.add_argument("--tile", type=int, default=-1, help="tile index for --watch-planning / --models (-1 = last)")
    ap.add_argument("--models", action="store_true", help="open model picker and list available models")
    ap.add_argument("--eval")
    ap.add_argument("--file")
    ap.add_argument("--all", action="store_true", help="run against every workbench page")
    ap.add_argument("--no-await", action="store_true")
    ap.add_argument("--key", help="send a TRUSTED key chord, e.g. 'Control+d' or 'Enter'")
    ap.add_argument("--focus-eval", help="JS to run (to set focus) before --key")
    args = ap.parse_args()

    try:
        page_targets()
    except Exception as e:
        print(f"ERROR: cannot reach {CDP}/json/list — is Cursor running with "
              f"--remote-debugging-port=9222 ? ({e})")
        sys.exit(2)

    if args.status:
        expr = js_bundle("tile_status.js", "status.js")
        ws_url, t = find_workbench()
        if not ws_url:
            print("no workbench page found"); sys.exit(3)
        print(f"# page: {t.get('title','')[:60]}")
        res, _ = evaluate(ws_url, expr, await_promise=False, want_console=False)
        print_result(res, [])
        return

    if args.models:
        js = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "list_models.js"), encoding="utf-8").read()
        js = js.replace("__TILE__", str(args.tile))
        ws_url, t = find_workbench()
        if not ws_url:
            print("no workbench page found"); sys.exit(3)
        print(f"# page: {t.get('title','')[:60]}")
        res, _ = evaluate(ws_url, js, await_promise=True, want_console=False)
        print_result(res, [])
        return

    if args.watch_planning:
        js = js_bundle("tile_status.js", "watch_planning.js")
        js = js.replace("__WAITMS__", str(int(args.wait * 1000))).replace("__TILE__", str(args.tile))
        ws_url, t = find_workbench()
        if not ws_url:
            print("no workbench page found"); sys.exit(3)
        print(f"# page: {t.get('title','')[:60]}")
        res, _ = evaluate(ws_url, js, await_promise=True, want_console=False)
        print_result(res, [])
        return

    if args.list:
        for t in page_targets():
            ed = "CHAT" if has_editor(t["webSocketDebuggerUrl"]) else "    "
            print(f"[{ed}] {t.get('title','')[:60]!r}  {t.get('url','')[:50]}")
        return

    if args.key:
        ws_url, t = find_workbench()
        if not ws_url:
            print("no workbench page found"); sys.exit(3)
        print(f"# page: {t.get('title','')[:60]}")
        send_chord(ws_url, args.key, focus_eval=args.focus_eval)
        print(f"sent chord: {args.key}")
        return

    expr = args.eval
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            expr = f.read()
    if expr is None:
        ap.error("provide --eval, --file, or --list")

    targets = all_workbench() if args.all else None
    if args.all:
        if not targets:
            print("no workbench pages found"); sys.exit(3)
        for t in targets:
            print(f"=== {t.get('title','')[:50]} ===")
            res, console = evaluate(t["webSocketDebuggerUrl"], expr, await_promise=not args.no_await)
            print_result(res, console)
        return

    ws_url, t = find_workbench()
    if not ws_url:
        print("no workbench page (with .tiptap.ProseMirror) found"); sys.exit(3)
    print(f"# page: {t.get('title','')[:60]}")
    res, console = evaluate(ws_url, expr, await_promise=not args.no_await)
    print_result(res, console)


if __name__ == "__main__":
    main()
