# CCXT 5-Second Candle Collector

Real-time 5-second OHLCV candle collector for Binance Futures using CCXT WebSocket.

## Structure

```
ccxt/
├── collector.py      # Main collector (streams trades → 5s candles)
├── client.py         # CCXT WebSocket client with trade aggregation
├── database.py       # SQLite storage
├── config.py         # Configuration (symbols, credentials)
├── viewer.py         # View collected data
├── start.sh          # Start collector in tmux
├── validator/
│   └── validate.py   # Validate 5s data against 1m exchange data
└── data/
    ├── candles_5s.db # SQLite database
    └── collector.log # Logs
```

## Quick Start

```bash
# 1. Start collector (runs in tmux background)
./start.sh

# 2. View collected data
python3 viewer.py

# 3. Validate data accuracy
python3 validator/validate.py
```

## Commands

### Start Collector
```bash
./start.sh
```
Starts the collector in a tmux session. It will:
- Stream trades via WebSocket
- Aggregate into 5-second candles
- Store in SQLite
- Auto-prune data older than 3 hours

### Monitor Collector
```bash
tmux attach -t ccxt_collector    # View live output
# Press Ctrl+B, D to detach
```

### Stop Collector
```bash
tmux kill-session -t ccxt_collector
```

### View Data
```bash
python3 viewer.py
```
Shows:
- Overview stats (total candles, volume, last update)
- Recent 15 candles per symbol

### Validate Data
```bash
python3 validator/validate.py
```
Fetches last 10 minutes of 1-minute candles from Binance and compares against aggregated 5-second data to verify accuracy.

## Configuration

Edit `config.py`:

```python
SYMBOLS = ["ETH/USDT:USDT"]     # Symbols to collect
TIMEFRAME_MS = 5000             # Candle interval (5 seconds)
HISTORY_MINUTES = 10            # Fetch last N mins of trades on startup
RETENTION_HOURS = 3             # Keep data for 3 hours
```

## Data Schema

```sql
CREATE TABLE candles (
    symbol TEXT,
    ts INTEGER,          -- Unix timestamp (seconds)
    open REAL,
    high REAL,
    low REAL,
    close REAL,
    volume REAL,
    trade_count INTEGER,
    PRIMARY KEY (symbol, ts)
);
```

## Requirements

- Python 3.8+
- ccxt
- tabulate

```bash
pip install ccxt tabulate
```
