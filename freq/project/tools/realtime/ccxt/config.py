#!/usr/bin/env python3
"""
Configuration for the CCXT 5-second data collector.
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = "/allah/data"
LOG_DIR = os.path.join(DATA_DIR, "logs")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Database
CANDLES_DB_PATH = os.path.join(DATA_DIR, "candles_5s.db")

# Exchange
EXCHANGE = "binance"
EXCHANGE_CREDENTIALS = {
    "apiKey": "ofQzX3gGAKS777NyYIovAy1XyqLzGC2UJPMh9jqIYEfieFRy3DCkZJl15VYA2zXo",
    "secret": "QVJpTFgHIEv74LmCT5clX8o1zAFEEqJqKpg2ePklObM1Ybv9iKNe8jvM7MRjoz07",
    "enableRateLimit": True,
    "options": {
        "defaultType": "future"
    }
}

# Symbols
SYMBOLS = ["ETH/USDT:USDT"]

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = os.path.join(LOG_DIR, "ccxt_collector.log")

# Retry settings
MAX_RECONNECT_ATTEMPTS = 5
RECONNECT_DELAY = 5

