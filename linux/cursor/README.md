# Cursor Agents Automation over CDP

Drive the **Cursor Agents** window from an external Python process using the Chrome
DevTools Protocol (CDP). No patching of Cursor — input is delivered as **trusted**
events (`isTrusted: true`) so it passes Cursor's strict keybinds (e.g. the Ctrl+D
tile split).

## Requirements

- Cursor launched with the remote debugging port:

  ```powershell
  Stop-Process -Name Cursor -Force; Start-Sleep 2
  Start-Process "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe" `
    -ArgumentList '--remote-debugging-port=9222','--remote-allow-origins=*'
  ```

  Verify: `http://127.0.0.1:9222/json/list` returns a JSON array of targets.

- Python dependency:

  ```bash
  pip install websocket-client
  ```

## Files

| File | Purpose |
|---|---|
| `cdp.py` | Raw CDP client + helpers: `--list`, `--status`, `--eval`, `--file`, `--key`, plus `click_at`, `hold_key`, `send_chord` |
| `workflow.py` | Full end-to-end runner (split → Auto → prompt → Opus → type → hold Enter) |
| `auto.py` | One-shot: split right → Auto → send → run N s → stop |
| `layout.js` | Layout detection, `snapshot()`, composer/editor/model-picker selectors |
| `tile_helpers.js` | `sleep`, `tiles()`, `selectModel`, `waitForAiResponse`, tile close helpers |
| `tile_status.js` | Per-tile status (model, planning, generating) |
| `prepare_one_tile.js` / `enforce_two_tiles.js` | Collapse / enforce tile counts |
| `workflow.js` | In-page phase: select Auto, type+send prompt, wait, select Opus |

## workflow.py

Runs from any directory (it resolves `import cdp` and the `.js` files relative to
its own location):

```bash
python "C:\Users\jar71\blue\linux\cursor\workflow.py"
```

Filtered output:

```bash
python "C:\Users\jar71\blue\linux\cursor\workflow.py" 2>&1 \
  | rg "prompt:|opusModel|typed|real click|baseline|enter_presses|planning_cleared|menu still"
```

### What it does

1. **connect** — picks the `[CHAT]` workbench page (`.tiptap.ProseMirror`), titled *Cursor Agents*.
2. **prepare** — best-effort collapse of extra tiles back to the base tile (non-fatal).
3. **split** — always a trusted **Ctrl+D**; the new tile's index is detected dynamically (last tile).
4. **phase** — on the new tile: select **Auto**, type + send the **auto prompt** (default: a timestamped *"stand by / do nothing"* instruction), wait for a response, then switch to **Opus 4.8 1M High**.
5. **type** — types the **Opus prompt** (default: an improvised *"directly invoke the mcp, don't do anything else first, keep the connection"* instruction) into the live **Send follow-up** composer.
6. **hold Enter** — holds Enter to nudge past Cursor's *"Planning next moves"* stuck-state, releasing once that indicator stays cleared.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `prompt` (positional) | timestamped *stand-by* prompt | the auto-phase prompt; a *"do nothing"* instruction if omitted |
| `--type-text` | improvised *invoke-mcp* prompt | the Opus prompt typed into the follow-up composer before the Enter hold |
| `--enter-interval` | `0.12` | seconds between autorepeat Enter ticks |
| `--max-secs` | `600` | safety cap for the Enter hold (10 min); `0` = unlimited |

### Key design notes

- **Targets the right composer.** A tile can contain multiple editors (an inline
  `.prompt-edit-input` edit box and the live `.agent-panel-followup-input`
  "Send follow-up"). All actions target the follow-up composer; the model picker
  and submit button are scoped to that composer's `.ui-prompt-input` container.
- **Real mouse click.** `real_focus` uses a trusted `Input.dispatchMouseEvent`
  click (not synthetic `.click()`) so it dismisses the open model-picker popover
  and focuses the composer; falls back to Escape + re-click if a popover lingers.
- **Holding Enter (not pressing).** `cdp.hold_key` sends **one** `keyDown`, then
  repeated `rawKeyDown` with `autoRepeat: true`, and **one** `keyUp` at the very
  end — the key is held the entire time (no intermediate release), matching the
  OS key-repeat behavior. The reported `enter_presses` is the autorepeat count.
- **Stop on planning-clear (debounced).** The *"Planning next moves"* shimmer
  (`.ui-collapsible-action.ui-collapsible-shimmer`, matched by `/planning next move/i`)
  flickers on/off while the agent works, so the runner only stops after it stays
  cleared for ~8 consecutive polls (~3s). Message count is **not** used (the list
  is virtualized).

## cdp.py

```bash
cd "C:\Users\jar71\blue\linux\cursor"
python cdp.py --list            # page targets; [CHAT] = workbench with composer
python cdp.py --status          # tiles, models, generating/planning state
python cdp.py --eval "1+1"      # evaluate JS in the workbench page
python cdp.py --file script.js  # evaluate a JS file
python cdp.py --key Control+d   # trusted Ctrl+D split only
python cdp.py --watch-planning --tile 1 --wait 20
```

## Troubleshooting

- **`no CDP workbench`** — Cursor isn't running with the debug flag, or the
  Agents window is closed. Re-launch with the flags above.
- **Wrong window** — multiple workbench pages exist; `find_workbench()` picks the
  first with a composer. Use `python cdp.py --list` to see titles.
- **`model not found`** — soft-fail; the run continues with the current model.
