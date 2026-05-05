# Baccarat Betting System

Automated Martingale betting for Pragmatic Play live baccarat on Stake.com.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  socks.js   │ →  │  pick.js    │ →  │  play.js    │      │
│  │  (pp API)   │    │  (pick API) │    │  (play API) │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│   WebSocket          Table Scoring       Martingale          │
│   Interceptor        & Selection         Execution           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
baccarat/
├── core/
│   ├── socks.js             # pp API - WebSocket data (v3.1)
│   ├── pick.js              # pick API - Randomness scoring (v3.1)
│   └── play.js              # play API - Martingale betting (v5.3)
├── legacy/                   # Old single-table scripts
│   ├── balance_result.js    # DOM balance + result detector (v7.0)
│   ├── fixed_bet.js         # Fixed $0.20 betting strategy (v7.0)
│   ├── popup.js             # Auto-dismiss inactivity popups (v1.0)
│   ├── table_monitor.js     # DOM table scraper (v1.0)
│   ├── unified.js           # Older balance+result (v6.0)
│   ├── balance.js           # Standalone balance detector (v1.5)
│   └── result.js            # Standalone result detector (v5.0)
├── static/
│   ├── simulate_click_player.js  # Click simulation helpers
│   └── find_all_games.js        # Enumerate Stake games
├── debug/
│   ├── fetch                # HAR WebSocket captures
│   ├── socks_v1             # Old socks version
│   └── socks_v2             # Old socks version
└── README.md
```

## Installation

Install all 3 scripts in Tampermonkey in order:

1. `core/socks.js` — `@run-at document-start`
2. `core/pick.js` — `@run-at document-start`
3. `core/play.js` — `@run-at document-end`

Target: `*://client.pragmaticplaylive.net/desktop/multibaccarat/*`

## Quick Start

```javascript
pp.status()       // all tables with P/B/T data
pick.status()     // scored tables ranked by randomness
play.start()      // start Martingale
play.stop()       // stop
play.status()     // current session state
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
play.start()               // start auto-betting
play.stop()                // stop
play.status()              // session state + P/L
play.reset()               // reset session counters

play.balance()             // current balance
play.profit()              // session profit in $
play.units()               // session profit in units
play.unitSize()            // current unit size

play.setTable(1)           // manually lock a table
play.clearUsed()           // allow reuse of exhausted tables

play.config                // modify config at runtime
play.state()               // raw state inspection
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
