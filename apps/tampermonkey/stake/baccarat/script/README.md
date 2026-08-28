# Stake Baccarat — Tampermonkey script

Untrusted-click fallback. Live betting is the Chrome extension in [`../extension/`](../extension/). Disable this userscript when the extension is loaded (double WebSocket hook otherwise).

## Install

1. Tampermonkey → create script from `stake-baccarat.js` (v7.2.1)
2. Optional: `stake-baccarat-pick-telegram-monitor.js` (v1.3.1)
3. Open Stake Multiplay. Inner frame must be `client.pragmaticplaylive.net/desktop/multibaccarat`
4. Console: `[SB] v7.2.1 · …` — not `· extension ·`

Clicks are `dispatchEvent` (not `isTrusted`). Prefer the extension.

## Files

```
script/
├── stake-baccarat.js                          # pp + pick + play HUD
├── stake-baccarat-pick-telegram-monitor.js    # optional Telegram
├── archive/  legacy/  static/                 # old TM snapshots
├── debug/    docs/    docker/                 # WS tooling / collector
├── elements.txt  fullele.txt                  # DOM dumps
└── README.md
```

Dump the **inner** multibaccarat frame into `elements.txt` when auditing DOM:

```javascript
document.querySelectorAll('[id^="TileHeight-"]').length  // > 0
```

## DOM (multibaccarat 1.3.30 / core 26.7.0)

| Role | Selector |
|---|---|
| Table tile | `[id^="TileHeight-"]` / `#TileHeight-{gameId}` |
| Player / Banker bet | `[data-betcode="0"]` / `[data-betcode="1"]` |
| Balance value | `[data-testid="wallet-balance-value"] span` |
| Chip $0.20 | `[data-testid="chip-stack-value-0.2"]` |

Hashed CSS classes (`.rM_r1`, `.lq_lv`, …) change between builds — do not use them.

## Console

```javascript
pp.status()
pick.status()
play.start()
play.stop()
play.status()
play.hud.hide()
play.hud.show()
```

Same `pp` / `pick` / `play` surface as the extension `page.js`. Full API was in the old baccarat README; the extension is the live copy.

## Docker WS collector

`docker/usage.md` — compose file is `script/docker/docker-compose.yml`.
