#!/bin/bash
pip install fastparquet matplotlib
cd /allah/blue/freq/project/tools

/allah/freqtrade/.venv/bin/python3 daily_trades.py
/allah/freqtrade/.venv/bin/python3 convert_to_feather.py
freqtrade download-data --userdir /allah/blue/freq/project/user_data --config /allah/blue/freq/project/user_data/config/main.json --timerange 20250801- --timeframes 1m 3m 5m 15m 30m 1h 4h --datadir /allah/freqtrade/user_data/data/binance
