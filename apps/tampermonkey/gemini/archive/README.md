# Gemini archive

Dated folders. Newest first. Live script is `../gemini.js` (3.0.0).

**Names:** `gemini-<role>.js.bak` · Tampermonkey zip snapshots `gemini-export-<role>.js.bak` · dumps `gemini-<role>.html`

Do not run anything here **and** `gemini.js` at the same time.

| Folder | What |
| --- | --- |
| `2026-08-14/` | Last four live scripts before unify |
| `2026-08-09/` | Pair-merges + TM export snapshots |
| `2026-06/` | Tab zoom |
| `2026-05/` | Auto Pro, Open Gem |
| `2026-03/` | DOM dump, read-aloud |
| `2026-02/` | Auto-think, slash/tab focus |

## `2026-08-14/`

| File | Was |
| --- | --- |
| `gemini-copy-response.js.bak` | copy auto + Ctrl+C |
| `gemini-notify-on-finish.js.bak` | finish toast |
| `gemini-ui.js.bak` | sidenav + mode + upsell |
| `gemini-input.js.bak` | fixed height + autofocus |

## `2026-08-09/`

Pair-merge sources → the 08-14 files:

| File | Role |
| --- | --- |
| `gemini-auto-copy.js.bak` + `gemini-copy-latest.js.bak` | → copy-response |
| `gemini-input-height.js.bak` + `gemini-auto-focus.js.bak` | → input |
| `gemini-sidenav.js.bak` + `gemini-mode-toggle.js.bak` + `gemini-upsell.js.bak` | → ui |
| `gemini-open-gem.js.bak` | Open Gem (disabled in TM backup) |

`gemini-export-*.js.bak` — Chrome TM backup 2026-08-08, extracted 08-09.
