#!/usr/bin/env python3
"""End-to-end Cursor Agents automation over CDP, with a snapshot at each step.

Stages:
  1. connect   — find the Cursor workbench page over CDP
  2. prepare   — best-effort collapse of extra tiles back to the base tile
  3. split     — ALWAYS a fresh trusted Ctrl+D split; the new tile index is
                 detected dynamically (it mounts at the end of the tile list)
  4. phase     — on the new tile: Auto -> send a "do nothing" prompt -> wait -> select Opus
  5. type      — type the Opus prompt (default: an improvised "directly invoke
                 the mcp, don't do anything else first, keep the connection" instruction)
                 into the Send follow-up composer
  6. hold      — HOLD Enter (one keyDown + autorepeat, single keyUp at the end) to
                 nudge past the "Planning next moves" stuck-state, releasing once
                 that indicator stays cleared (debounced), capped by --max-secs

Requires Cursor launched with:
    --remote-debugging-port=9222 --remote-allow-origins=*

Runs from any working directory (paths are resolved relative to this file):
    python "C:\\Users\\jar71\\blue\\linux\\cursor\\workflow.py"
"""
import argparse
import json
import random
import sys
import time

import cdp


# Auto phase only exists to spin up the tile before we switch to Opus, so we
# don't want Auto to actually start working — just stand by. Each prompt leads
# with a timestamp (added in auto_prompt()) and then a strongly-emphasized
# standby instruction. Lightly varied so each run looks a little different.
AUTO_PROMPTS = [
    "STAND BY. Do NOT do anything yet — don't read, edit, run, or plan anything. Just wait for my next instruction.",
    "STAND BY and do NOTHING. Don't read files, don't run commands, don't make changes. Wait silently for my next message.",
    "IMPORTANT: STAND BY. Take NO action of any kind right now. Just hold and wait for my next instruction.",
    "Just STAND BY. Don't do anything at all — no actions, no analysis. Wait for what I send next.",
]

# Opus phase prompt: kick the MCP connection immediately and keep it open,
# without doing anything else first. Improvised phrasings, same intent.
OPUS_PROMPTS = [
    "Directly invoke the mcp. Don't do anything else first, and keep the mcp connection open.",
    "Invoke the mcp right away — don't do anything else beforehand, and keep the mcp connection alive.",
    "Call the mcp directly. Do nothing else first, and keep the mcp connection running.",
    "Start by invoking the mcp directly. Don't do anything else first, and hold the mcp connection open.",
]


def js_bundle(*names, **subs):
    js = cdp.js_bundle("layout.js", "tile_status.js", "tile_helpers.js", *names)
    for key, val in subs.items():
        js = js.replace(key, str(val))
    return js


def eval_js(ws, js, await_promise=True):
    res, _ = cdp.evaluate(ws, js, await_promise=await_promise, want_console=False)
    exc = res.get("exceptionDetails")
    if exc:
        print("EXCEPTION", json.dumps(exc.get("exception", exc))[:600])
    return res.get("result", {}).get("value")


def snap(ws, label):
    s = eval_js(ws, js_bundle() + "\n; snapshot();", False)
    print(f"CDP [{label}]:", json.dumps(s, indent=2)[:1200])
    return s


def auto_prompt():
    """Initial Auto prompt: a leading timestamp, then a strong standby instruction."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    return f"[{ts}] {random.choice(AUTO_PROMPTS)}"


def opus_prompt():
    """Improvised Opus prompt: invoke the mcp directly and keep it connected."""
    return random.choice(OPUS_PROMPTS)


def tile_focus_eval(idx):
    """JS that focuses the LIVE 'Send follow-up' composer inside tile `idx`.

    Ignores inline edit boxes (.prompt-edit-input); prefers the follow-up input,
    falling back to the last real composer. Negatives count from the end.
    """
    return (
        "(()=>{"
        "const ts=[...document.querySelectorAll('.glass-agent-conversation-tiling__tile')];"
        f"const root=ts.length?ts.at({idx}):document;"
        "if(!root)return false;"
        "const eds=[...root.querySelectorAll('.tiptap.ProseMirror.ui-prompt-input-editor__input')]"
        ".filter(e=>!e.closest('.prompt-edit-input'));"
        "const isFu=e=>e.closest('.agent-panel-followup-input')||/send follow-?up/i.test("
        "(e.querySelector('[data-placeholder]')?.getAttribute('data-placeholder'))"
        "||e.getAttribute('data-placeholder')||'');"
        "const ed=eds.find(isFu)||eds[eds.length-1];"
        "if(!ed)return false;ed.focus();return true;})()"
    )


def fail(message, payload=None):
    print(f"ERROR: {message}")
    if payload and payload.get("log"):
        for line in payload["log"][-6:]:
            print(" ", line)
    sys.exit(1)


def connect():
    ws, page = cdp.find_workbench()
    if not ws:
        print("ERROR: no CDP workbench"); sys.exit(3)
    print(f"# page: {page.get('title', '')[:60]}")
    return ws


def tile_count(ws):
    return eval_js(
        ws, "document.querySelectorAll('.glass-agent-conversation-tiling__tile').length",
        await_promise=False,
    ) or 0


def prepare(ws):
    """Best-effort collapse of extra tiles back to the base tile (non-fatal)."""
    prep = eval_js(ws, js_bundle("prepare_one_tile.js"))
    print("prepare:", json.dumps(prep, indent=2)[:800])
    if not prep or prep.get("error"):
        print("WARN: prepare/collapse did not fully succeed — continuing (Ctrl+D will add a new tile)")
    return prep


def split(ws):
    """Always start with a fresh trusted Ctrl+D split; return the NEW tile's index.

    The new tile mounts at the end of the tile list, so its index is the last one.
    We detect it dynamically rather than assuming index 1, which keeps the workflow
    robust no matter how many tiles already exist.
    """
    before = tile_count(ws)
    print(f"split: Ctrl+D to open a new tile (tiles before={before})")
    cdp.send_chord(ws, "Control+d", focus_eval=tile_focus_eval(-1))

    new_idx = max(0, before)  # fallback if count never grows (single-pane -> tile 1)
    for _ in range(40):
        time.sleep(0.15)
        count = tile_count(ws)
        if count > before:
            new_idx = count - 1
            break
    snap(ws, "after-split")
    print(f"split: new tile index = {new_idx} (tiles now={tile_count(ws)})")
    return new_idx


def run_phase(ws, prompt, idx):
    """On the NEW tile `idx`: select Auto, type+send prompt, wait, then switch to Opus."""
    phase = eval_js(ws, js_bundle("workflow.js", __TARGET__=idx, __PROMPT__=json.dumps(prompt)))
    summary = {k: phase.get(k) for k in phase if k not in ("log", "snapshot")} if phase else phase
    print("phase:", json.dumps(summary, indent=2))
    snap(ws, "after-phase")

    if phase and not phase.get("error"):
        return phase.get("idx", idx)

    soft_fails = {"model not found", "no ai response on NEW tile"}
    if phase and phase.get("error") in soft_fails:
        print(f"WARN: {phase['error']} — continuing Enter spam with current model")
        return idx

    fail("phase failed", phase)


def editor_center(ws, idx):
    """Viewport center of tile `idx`'s LIVE follow-up composer, or None."""
    js = js_bundle() + (
        f"\n;(()=>{{const ed=editorIn({idx});if(!ed)return null;"
        "const r=ed.getBoundingClientRect();"
        "return {x:Math.round(r.left+r.width/2),y:Math.round(r.top+r.height/2)};})()"
    )
    return eval_js(ws, js, await_promise=False)


def menu_open(ws):
    """True if any popover menu/option (e.g. the model picker) is visible."""
    return bool(eval_js(
        ws,
        "[...document.querySelectorAll('[role=\"option\"],[role^=\"menuitem\"]')]"
        ".some(e=>e.offsetParent)",
        await_promise=False,
    ))


def real_focus(ws, idx):
    """Mimic a real click into the tile's text area (closes open popovers)."""
    pt = editor_center(ws, idx)
    if not pt:
        print("WARN: editor not found for real click — falling back to focus()")
        eval_js(ws, tile_focus_eval(idx), await_promise=True)
        return
    cdp.click_at(ws, pt["x"], pt["y"])
    time.sleep(0.25)
    if menu_open(ws):
        # lingering popover (e.g. model picker) — dismiss with Escape, then re-click
        eval_js(ws, "document.dispatchEvent(new KeyboardEvent('keydown',"
                    "{key:'Escape',code:'Escape',bubbles:true}));true;", await_promise=False)
        time.sleep(0.15)
        cdp.click_at(ws, pt["x"], pt["y"])
        time.sleep(0.15)
    print(f"real click at {pt}; menu still open: {menu_open(ws)}")


def type_in_composer(ws, idx, text):
    """Real-click the follow-up composer, then insert `text` (replacing any draft)."""
    real_focus(ws, idx)
    tmpl = (
        "\n;(()=>{const ed=editorIn(__IDX__);if(!ed)return {ok:false};"
        "ed.focus();document.execCommand('selectAll',false,null);"
        "document.execCommand('insertText',false,__TEXT__);"
        "return {ok:true,text:(ed.textContent||'').slice(0,40)};})()"
    )
    js = js_bundle() + tmpl.replace("__IDX__", str(idx)).replace("__TEXT__", json.dumps(text))
    r = eval_js(ws, js)
    print(f"typed {text!r} into composer: {r}")
    return r


def response_state(ws, idx):
    """Current AI-response state of tile `idx`: count, planning flag, last text."""
    tmpl = (
        "\n;(()=>{const idx=__IDX__;"
        "const t=tiles().length?tileAt(idx):document;"
        "const sh=t?.querySelector('.ui-collapsible-action.ui-collapsible-shimmer')?.textContent||'';"
        "const text=latestAiText(idx)||'';"
        "return {aiCount:aiMessagesInTile(idx).length,"
        "planning:/planning\\s+next\\s+move/i.test(sh),"
        "generating:!!stopInIdx(idx),lastText:text.slice(0,120)};})()"
    )
    return eval_js(ws, js_bundle() + tmpl.replace("__IDX__", str(idx)), await_promise=False) or {}


def response_stop_eval(idx, clear_polls=8):
    """JS: truthy once the 'Planning next moves' indicator has APPEARED and then
    stayed CLEARED for `clear_polls` consecutive polls on tile `idx`.

    Works around the Cursor bug where the agent gets stuck on 'Planning next
    moves'; we hold Enter to nudge it, and stop once that indicator is gone for
    good (the response has rendered). The shimmer flickers on/off while the agent
    works, so a single cleared poll is not enough — we debounce with a streak
    counter and only stop after a sustained clear.
    """
    return (
        "(()=>{const idx=" + str(idx) + ",need=" + str(clear_polls) + ";"
        "const t=tiles().length?tileAt(idx):document;"
        "const sh=t?.querySelector('.ui-collapsible-action.ui-collapsible-shimmer')?.textContent||'';"
        "const planning=/planning\\s+next\\s+move/i.test(sh);"
        "if(planning){window.__wfPlanned=true;window.__wfClear=0;}"
        "else if(window.__wfPlanned){window.__wfClear=(window.__wfClear||0)+1;}"
        "return !!window.__wfPlanned&&!planning&&(window.__wfClear>=need);})()"
    )


def enter_until_response(ws, idx, interval, max_secs):
    """Click into the composer, then HOLD Enter until 'Planning next moves' clears."""
    cap = f"{max_secs}s cap" if max_secs else "unlimited"
    print(f"hold Enter until planning clears on tile {idx} ({cap})")
    real_focus(ws, idx)
    time.sleep(random.uniform(0.3, 0.7))

    eval_js(ws, "window.__wfPlanned=false; window.__wfClear=0; true;", await_promise=False)
    base = response_state(ws, idx)
    print(f"baseline: generating={base.get('generating')}, planning={base.get('planning')}")

    presses = cdp.hold_key(
        ws, "Enter", interval=interval, focus_eval=tile_focus_eval(idx),
        stop_eval=response_stop_eval(idx), max_secs=(max_secs or None),
    )

    final = response_state(ws, idx)
    snap(ws, "done")
    print(f"enter_presses={presses}; planning_cleared={not final.get('planning')}; "
          f"planning={final.get('planning')}, lastText={final.get('lastText', '')[:80]!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prompt", nargs="?")
    ap.add_argument("--enter-interval", type=float, default=0.12)
    ap.add_argument("--max-secs", type=float, default=600.0, help="safety cap for Enter hold in seconds (default 600 = 10 min; 0 = unlimited)")
    ap.add_argument("--type-text", default=None,
                    help="Opus prompt to type into the composer before Enter spam "
                         "(default: an improvised 'directly invoke the mcp' instruction)")
    args = ap.parse_args()

    prompt = args.prompt or auto_prompt()
    type_text = args.type_text or opus_prompt()
    print(f"# auto prompt: {prompt!r}")
    print(f"# opus prompt: {type_text!r}")

    ws = connect()
    snap(ws, "initial")

    prepare(ws)
    idx = split(ws)
    idx = run_phase(ws, prompt, idx)
    type_in_composer(ws, idx, type_text)
    enter_until_response(ws, idx, args.enter_interval, args.max_secs)


if __name__ == "__main__":
    main()
