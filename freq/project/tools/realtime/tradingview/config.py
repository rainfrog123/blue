"""TradingView collector configuration."""

import os
import sys
from pathlib import Path

# Add cred_loader to path (tradingview -> realtime -> tools -> project -> freq -> blue -> linux/extra)
sys.path.insert(0, str(Path(__file__).parents[5] / "linux" / "extra"))
from cred_loader import get_tradingview

BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "tv_candles.db")
LOG_FILE = os.path.join(DATA_DIR, "collector.log")

# Auth token loaded from secure credentials file
AUTH_TOKEN = get_tradingview()["auth_token"]

# Symbols
SYMBOLS = ["BINANCE:ETHUSDT.P"]
TIMEFRAME = "5S"
INITIAL_BARS = 300
RETENTION_HOURS = 3
PRUNE_INTERVAL = 600

LOG_LEVEL = "INFO"

