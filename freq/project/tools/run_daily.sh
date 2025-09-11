#!/bin/bash

cd /allah/blue/freq/project/tools

/allah/freqtrade/.venv/bin/python3 daily_trades.py
/allah/freqtrade/.venv/bin/python3 convert_to_feather.py
