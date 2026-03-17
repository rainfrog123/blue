# Backtesting Commands

freqtrade backtesting --strategy TemaSlope --userdir /allah/blue/freq/project/user_data --config /allah/blue/freq/project/user_data/config/backtest.json --timerange 1761501600-1761505200 --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0

freqtrade backtesting --strategy TemaSlope --userdir /allah/blue/freq/project/user_data --config /allah/blue/freq/project/user_data/config/backtest.json --timerange 20251101- --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0

# VWAP strategy backtest
freqtrade backtesting --strategy VwapCross --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/backtest.json --timerange 20260310- --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0
