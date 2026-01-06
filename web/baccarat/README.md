# Baccarat Betting System

A 3-script automated betting system for Pragmatic Play live baccarat.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     BETTING SYSTEM                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  socks.js   │ →  │  pick.js    │ →  │  play.js    │         │
│  │  (pp API)   │    │  (pick API) │    │  (play API) │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│       ↓                   ↓                   ↓                 │
│   WebSocket          Selection            Execution             │
│   Data               Rules                Betting               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
baccarat/
├── core/                    # Core betting system
│   ├── socks.js            # pp API - WebSocket data collection
│   ├── pick.js             # pick API - Table selection rules
│   └── play.js             # play API - Bet execution
├── debug/                   # Debug/development data
│   ├── fetch               # HAR WebSocket captures
│   ├── socks_v1            # Old socks version
│   └── socks_v2            # Old socks version
├── legacy/                  # Old/unused scripts
│   └── *.js
└── static/                  # Static resources
```

## Installation

Install all 3 scripts in Tampermonkey in this order:
1. `core/socks.js` (runs at document-start)
2. `core/pick.js` (runs at document-start)
3. `core/play.js` (runs at document-end)

## Quick Start

```javascript
// View all tables with P/B/T data
pp.status()

// View eligible tables with selection analysis
pick.status()

// Start auto-betting
play.start()

// Stop
play.stop()
```

## API Reference

### pp API (socks.js) - Data Collection

```javascript
pp.status()              // Print all tables
pp.list()                // Array of tables with stats
pp.get(1)                // Get table by UID
pp.get("tableId")        // Get table by ID
pp.pbt(1)                // Get P/B/T sequence as array
pp.pbtStr(1)             // Get P/B/T sequence as string
pp.lastN(1, 10)          // Get last N results
pp.tables()              // All table data
pp.count()               // Number of tables
```

### pick API (pick.js) - Selection Rules

```javascript
pick.status()            // Print eligible tables with analysis
pick.pick()              // Quick pick: {table, side}
pick.all()               // All eligible tables
pick.byRatio()           // Sorted by ratio (best first)
pick.streaky()           // Tables with actionable streaks
pick.suggest(table)      // Suggest 'P' or 'B' for table

// Modify rules at runtime
pick.rules.MIN_ROUNDS = 30
pick.rules.MAX_PB_DIFF = 5
pick.rules.MIN_STREAK_FOR_BET = 4
```

### play API (play.js) - Bet Execution

```javascript
play.start()             // Start auto-betting
play.stop()              // Stop auto-betting
play.status()            // Current status
play.print()             // Print summary

play.balance()           // Current balance
play.profit()            // Total profit
play.summary()           // Full stats

play.bet(1, 'P', 3)      // Manual: bet on table 1, Player, 3 clicks
play.player(0, 5)        // Manual: bet Player on tile 0
play.banker(0, 5)        // Manual: bet Banker on tile 0
```

## Selection Rules (pick.js)

| Rule | Default | Description |
|------|---------|-------------|
| MIN_ROUNDS | 20 | Minimum games before eligible |
| MAX_PB_DIFF | 3 | Maximum \|P-B\| difference |
| REQUIRE_CAN_BET | true | Must be open for betting |
| MAX_RATIO | 0.15 | Maximum ratio for eligibility |
| MIN_STREAK_FOR_BET | 3 | Bet against streak if >= this |

## Selection Logic

1. **Filter**: Tables must pass MIN_ROUNDS, MAX_PB_DIFF, canBet, MAX_RATIO
2. **Score**: Rank by ratio (lower = more balanced)
3. **Side**: If streak ≥ 3, bet against it; otherwise bet on underdog

