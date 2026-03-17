"""CCXT 5-second candle collector configuration."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[4] / "linux" / "extra"))
from cred_loader import get_binance

BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "candles_5s.db")
LOG_FILE = os.path.join(DATA_DIR, "collector.log")

_creds = get_binance()
EXCHANGE = "binance"
EXCHANGE_CREDENTIALS = {
    "apiKey": _creds["api_key"],
    "secret": _creds["api_secret"],
    "options": {"defaultType": "future"}
}

SYMBOLS = ["ETH/USDT:USDT"]
TIMEFRAME_MS = 5000
HISTORY_MINUTES = 10
RETENTION_HOURS = 3
PRUNE_INTERVAL = 600

LOG_LEVEL = "INFO"
