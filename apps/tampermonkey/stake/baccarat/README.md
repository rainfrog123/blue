# Baccarat Betting System

Automated Paroli / Martingale betting for Pragmatic Play live multibaccarat on Stake.com.

**Live path is the Chrome extension** in `extension/` (v8.1.0). Tampermonkey `stake-baccarat.js` is the untrusted-click fallback — disable it when the extension is loaded.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Chrome extension (extension/)                                  │
│                                                                 │
│  page.js MAIN world     content.js isolated     background.js   │
│  WS + pick + play HUD   postMessage bridge      debugger CDP    │
│  document_start         trustedClick relay      Input.mouse     │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
stake/baccarat/
├── extension/              # LIVE — Load unpacked in chrome://extensions
│   ├── manifest.json
│   ├── background.js       # chrome.debugger Input.dispatchMouseEvent
│   ├── content.js          # isolated bridge
│   ├── page.js             # HUD + betting (MAIN world)
│   ├── popup.html
│   └── README.md
├── stake-baccarat.js       # Tampermonkey fallback (untrusted clicks)
├── stake-baccarat-pick-telegram-monitor.js
├── archive/
├── legacy/
├── static/
├── debug/
└── README.md
```

## Installation

1. Chrome → `chrome://extensions` → Developer mode → **Load unpacked**
2. Select `C:\Users\jar71\blue\apps\tampermonkey\stake\baccarat\extension`
3. Open Stake Multiplay. Inner frame must be `client.pragmaticplaylive.net/desktop/multibaccarat`
4. Console: `[SB] v8.1.0 · extension · …` HUD title **Play HUD · ext**
5. Disable Tampermonkey `stake-baccarat.js` (double WebSocket hook otherwise)

Chrome shows **“debugging this browser”** while the debugger is attached. That is required for `isTrusted` clicks. Hard-refresh after extension reload.

Dump the **inner** multibaccarat frame (not Stake mini-play / shell iframes) into `elements.txt` when auditing DOM. Confirm with:

```javascript
document.querySelectorAll('[id^="TileHeight-"]').length  // > 0
```

## DOM (multibaccarat 1.3.30 / core 26.7.0)

Stable selectors used by play + helpers:

| Role | Selector |
|---|---|
| Table tile | `[id^="TileHeight-"]` / `#TileHeight-{gameId}` |
| Player / Banker bet | `[data-betcode="0"]` / `[data-betcode="1"]` |
| Balance value | `[data-testid="wallet-balance-value"] span` |
| Chip $0.20 | `[data-testid="chip-stack-value-0.2"]` |

Hashed CSS classes (`.rM_r1`, `.lq_lv`, …) change between builds — do not use them.

Unified `8.1.0` (extension `page.js`) hunts after-T tables **concurrently** (does not wait for a result before the next place). Trusted CDP clicks. Telegram monitor `1.3.1` is optional.

## Quick Start

The play HUD appears on the multibaccarat page after `page.js` loads. Use it instead of the console.

```javascript
pp.status()       // all tables with P/B/T data
pick.status()     // scored tables ranked by randomness
play.start()      // start (also the HUD Start button)
play.stop()       // stop
play.status()     // current session state
play.hud.hide()   // hide the panel
play.hud.show()   // show it again
```

## API Reference

### pp (socks.js) — WebSocket Data

Intercepts Pragmatic Play WebSocket messages and builds a live table map.

```javascript
pp.status()                // print all tables
pp.list()                  // array of tables with stats + last 10 results
pp.get(1)                  // get table by UID (number)
pp.get("cbcf...")          // get table by gameId (string)
pp.get("422")              // get table by lobbyId (string)
pp.betting()               // tables currently open for betting
pp.count()                 // number of tables
pp.msgs()                  // total WS messages received

// sequences
pp.pbt(1)                  // P/B/T sequence as array ['P','B','T',...]
pp.pbtStr(1)               // sequence as string "PBTPBBPB..."
pp.lastN(1, 10)            // last N results
pp.sequences()             // all tables with full sequences
pp.seqAll()                // print all sequences

// ID mapping
pp.gameToLobby("cbcf..")   // gameId → lobbyId
pp.lobbyToGame("422")      // lobbyId → gameId

// misc
pp.road(1)                 // raw bigRoad data
pp.tables()                // all table data as object
pp.configs()               // raw tableconfig data
pp.export()                // JSON dump
pp.clear()                 // reset everything
```

### pick (pick.js) — Table Scoring

Scores tables 0–100 based on randomness. Higher = more like a fair coin flip = better.

```javascript
pick.status()              // all tables ranked with scores
pick.summary()             // quick top 5 list
pick.check(1)              // detailed score breakdown for a table
pick.best()                // single best eligible table
pick.top(5)                // top N eligible tables
pick.eligible()            // all eligible tables (score >= 35)
pick.all()                 // all scored tables
pick.pick()                // { table, score }

// analysis helpers
pick.streak(1)             // current streak for table
pick.longest(1)            // longest streak for table
pick.chop(1)               // alternation count in last 12

pick.help()                // full scoring docs
```

#### Scoring Breakdown

| Factor | Range | Weight | What it measures |
|---|---|---|---|
| balance | -10 to 40 | high | P/B ratio equality (<=0.06 = 36+) |
| ties | -25 to 30 | high | low tie % (<5% = 25+) |
| patternQuality | -15 to 20 | med | randomness in last 20 hands |
| randomness | -15 to 15 | med | alternation count in last 12 |
| history | 0 to 15 | med | more rounds = more reliable |
| recent | -8 to 10 | low | last 6 hands randomness |
| currentStreak | -5 to 5 | low | short streaks good, long bad |
| canBet | 0 to 5 | low | betting window open bonus |

Hard reject (score = 0): total < 30 rounds, or <= 3 alternations in last 12.

### play (play.js) — Martingale

Classic Martingale: win resets to 1 unit, loss doubles (1→2→4).

```javascript
play.start()               // start auto-betting (HUD Start)
play.stop()                // stop
play.status()              // session state + P/L (console)
play.snapshot()            // same data, no console dump
play.reset()               // reset session counters

play.balance()             // current balance
play.profit()              // session profit in $
play.units()               // session profit in units
play.unitSize()            // current unit size

play.setTable(1)           // manually lock a table (or click a HUD row)
play.clearUsed()           // allow reuse of exhausted tables

play.config                // modify config at runtime
play.state()               // raw state inspection
play.hud.hide()            // hide the on-page panel
play.hud.show()            // show it again
```

#### Configuration

```javascript
play.config.STEPS = [1, 2, 4]       // unit multipliers per step
play.config.UNIT_FRACTION = 1/7     // unit = balance * this
play.config.MIN_UNIT = 0.2          // minimum unit ($)
play.config.SESSION_STOP_LOSS = -6  // stop at -6 units
play.config.SESSION_STOP_WIN = 3    // take profit at +3 units
play.config.SIDE = null             // null=random, 'P'=player, 'B'=banker
play.config.CHIP_VALUE = 0.20      // $ per click
play.config.BET_DELAY = 2000       // ms between bet attempts
play.config.WAIT_FOR_RESULT = 30000 // max wait for result (ms)
```

#### Strategy

1. Unit size = balance / 7 at session start (min $0.20)
2. Pick best table via `pick.eligible()`
3. Bet 1 unit on random side (coin flip)
4. Win → reset to 1 unit, Loss → double (1→2→4)
5. Max loss on one sequence: 7 units (1+2+4) → move to new table
6. Take profit at +3 units → start new session with recalculated unit
7. Stop-loss at -6 units → start new session or stop if balance too low
