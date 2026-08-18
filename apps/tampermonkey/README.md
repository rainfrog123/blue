# Tampermonkey scripts

Canonical tree. Chrome export snapshot: `backup/Tampermonkey Backup YYYY-MM-DD/` (export names unchanged).

**Live kebab-case files** · superseded → `archive/*.bak`.

## Import

Zip: `import/tampermonkey-live-active.zip`

Folder: `import/tampermonkey-live-active/`

Disable old split Gemini / baccarat entries before import.

## Live install set

| File | Role |
| --- | --- |
| `gemini/gemini.js` | Unified 3.0.0 — copy + toast + sidenav/mode/upsell + input |
| `caixin/caixin-reader-relogin-and-block-redirect.js` | Relogin + block global redirect |
| `twitter/twitter-ui-cleanup-hide-pill-and-verified.js` | Hide pill + remove verified |
| `xiaohongshu/xiaohongshu-ctrl-click-new-tab.js` | Ctrl+Click new tab |
| `xiaomi/xiaomi-router-auto-login.js` | LuCI auto-login |
| `stake/blackjack/stake-blackjack-dom-automation.js` | DOM automation |
| `stake/baccarat/stake-baccarat.js` | Unified 7.0.0 — pp + pick + play HUD |
| `stake/baccarat/stake-baccarat-pick-telegram-monitor.js` | Optional Telegram |
| `hyperliquid/hyperliquid-light-theme.js` | Light chrome for app.hyperliquid.xyz |

`gemini/zoom-per-tab-ext/` is a Chrome extension, not TM.
