# Stake Baccarat — Chrome extension

MV3 unpacked extension. Same HUD / pick / play as the Tampermonkey script, but clicks use `chrome.debugger` `Input.dispatchMouseEvent` (trusted browser input) instead of page `dispatchEvent`.

## Load

1. Chrome → `chrome://extensions` → Developer mode → **Load unpacked**
2. Pick this folder: `C:\Users\jar71\blue\apps\tampermonkey\stake\baccarat\extension`
3. Open Stake Multiplay (inner frame `client.pragmaticplaylive.net/desktop/multibaccarat`)
4. Console should log `[SB] v8.1.0 · extension · …`
5. **Disable** Tampermonkey `stake-baccarat.js` so the WebSocket is not hooked twice

Hard-refresh the Multiplay iframe after reloading the extension.

**8.1.0 concurrent hunt:** after a place, the loop keeps scanning other after-T tables. Results settle in the background. HUD phase shows `N live`. Serial wait: `play.config.CONCURRENT = false`.

## Why debugger

Page JS cannot set `isTrusted`. The extension attaches to the **multibaccarat iframe target** (not only the top-level tab) so CSS-pixel coords from `getBoundingClientRect()` match the CDP mouse viewport.

Chrome shows an infobar: “Stake Baccarat started debugging this browser.” That is the permission cost of trusted clicks. Do not hide it.

If attach fails (another debugger, missing iframe target), clicks fall back to the old synthetic events.

## Files

| File | World | Job |
|---|---|---|
| `manifest.json` | — | MV3, `debugger` permission, MAIN + ISOLATED content scripts at `document_start` |
| `page.js` | MAIN | WS hook, HUD, betting (live copy of the old userscript) |
| `content.js` | ISOLATED | `postMessage` ↔ `chrome.runtime` |
| `background.js` | SW | Attach iframe target, `Input.dispatchMouseEvent` |
| `popup.html` | — | Short reminder |

Keep `stake-baccarat.js` in the parent folder as a Tampermonkey fallback only (untrusted clicks).
