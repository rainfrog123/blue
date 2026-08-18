# Hyperliquid Light Theme

Tampermonkey userscript. Light chrome for [app.hyperliquid.xyz](https://app.hyperliquid.xyz/).

v1.8: leverage slider (track / fill / thumb) and `button[color=primary]` stay mint — they were painted white. v1.7 still polishes TV invert edges.

| File | Role |
| --- | --- |
| `hyperliquid-light-theme.js` | Live userscript |
| `elements.txt` | DOM/color dump used to build the map |

Keeps green / red PnL and mint accents. Does not restyle the TradingView iframe (cross-origin; stays dark).

## Install

1. Tampermonkey → Create a new script
2. Paste `hyperliquid-light-theme.js`
3. Save, reload the trade page
