# Stake Baccarat — Chrome extension

MV3 unpacked extension. HUD lives in the **Multiplay iframe**. Clicks use `chrome.debugger` `Input.dispatchMouseEvent`.

## Load

1. Chrome → `chrome://extensions` → Developer mode → **Load unpacked**
2. Pick this folder: `C:\Users\jar71\Music\blue\apps\tampermonkey\stake\baccarat\extension`
3. Open Stake Multiplay (inner frame `client.pragmaticplaylive.net/desktop/multibaccarat`)
4. Iframe console: `[SB] v8.2.2 · extension · pp + pick + play HUD`
5. Stake tab (optional): `[SB] v8.2.2 · extension · focus + wallet relay`
6. **Disable** Tampermonkey `../script/stake-baccarat.js` so the WebSocket is not hooked twice

Reload the extension, then hard-refresh Stake. Last-used **Side / Mode / Hunt / P/B random** and HUD size come from `chrome.storage`. **–** collapses to the title bar; drag edges to resize.

Toolbar: gold chip icon + popup (Open Stake / Reload HUD).

**8.2.3:** Extension icons + toolbar popup.

**8.2.2:** `createPlay` needed `WALLET_VALUE_SELS` after the split (console: `ReferenceError` at play.js:90). CSP warnings on Stake are report-only and not the HUD.

**8.2.1:** HUD mount used `HUD_WIDTH` after the `src/` split without aliasing it — panel never attached. Aliased + boot no longer swallows `window.play` if HUD throws.

**8.2.0:** MAIN world split into `src/` (`ns` → `focus` → `bridge` → `util` → `pp` → `pick` → `play` → `boot`). Same HUD / hunt / skip-min as 8.1.18.

**8.1.18:** Planned stake below table min is **skipped** (a $0.20 unit never becomes a $1 bet on a $1-min table).

**8.1.17:** HUD default **400×440**. Controls are compact; the log is a monospace pane that fills the rest. Saved 760×560 resets once. Drag edges if you want it taller.

**8.1.16:** Support popup OK is found by label if PP dropped the old `data-testid`s. CDP click goes through the HUD. Retries if the dialog stays.

**8.1.15:** HUD is in the Multiplay iframe again. Stake only relays wallet + focus.

**8.1.14:** Drag the HUD edges or the bottom-right grip to resize. Size is saved.

**8.1.13:** HUD collapses to the title bar (no leftover min-height).

**8.1.10:** $0.20 bets always select the $0.20 chip before P/B.

**8.1.9:** CDP `Emulation.setFocusEmulationEnabled` on Stake + Multiplay iframe.

## Why debugger

Page JS cannot set `isTrusted`. The extension attaches to the **multibaccarat iframe target** so CSS-pixel coords match the CDP mouse viewport.

Chrome shows an infobar: “Stake Baccarat started debugging this browser.” That is expected.

## Files

| File | World | Job |
| --- | --- | --- |
| `manifest.json` | — | MV3, `debugger` + `storage` |
| `src/ns.js` | MAIN | `window.__SB` + version |
| `src/focus.js` | MAIN | Visibility / focus mask |
| `src/bridge.js` | MAIN | `postMessage` storage + HUD bus + wallet |
| `src/util.js` | MAIN | CDP click + helpers |
| `src/pp.js` | MAIN | WebSocket table map |
| `src/pick.js` | MAIN | Scoring / firewall |
| `src/play.js` | MAIN | HUD, hunt, chips, progression |
| `src/boot.js` | MAIN | Host gate; wires `pp` / `pick` / `play` |
| `content.js` | ISOLATED | `postMessage` ↔ `chrome.runtime` |
| `background.js` | SW | CDP clicks + HUD bus |
| `popup.html` / `popup.css` / `popup.js` | — | Toolbar menu |
| `icons/` | — | Chip icon 16–128 |

Tampermonkey fallback lives in [`../script/stake-baccarat.js`](../script/stake-baccarat.js) (untrusted clicks). Do not run it with this extension.
