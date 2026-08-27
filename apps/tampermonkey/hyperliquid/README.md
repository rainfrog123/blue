# Hyperliquid Light Theme

Tampermonkey userscript. Light chrome for [app.hyperliquid.xyz](https://app.hyperliquid.xyz/).

**v1.10.0** — no dark first-paint. `html` is painted the page fill immediately; `body` / `#root` stay invisible until the tree is lit, then they show already light.

**v1.9.0** — hover/focus, new dark greys, slider / primary mint. TradingView is inverted (not native light).

| File | Role |
| --- | --- |
| `hyperliquid-light-theme.js` | Live userscript |
| `elements.txt` | Older DOM/color dump |

Keeps green / red PnL and mint accents. The chart iframe stays `theme-dark` inside; the script inverts that document (`invert(1) hue-rotate(180deg)`).

## Install

1. Tampermonkey → existing script or new
2. Paste `hyperliquid-light-theme.js`
3. Save, hard-reload the trade page
4. Console: `[HL Light] 1.10.0 — no dark first paint`
