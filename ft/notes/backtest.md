# Backtesting Commands

freqtrade backtesting --strategy bt_TemaSlope --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/bt_backtest.json --timerange 1761501600-1761505200 --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0

freqtrade backtesting --strategy bt_TemaSlope --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/bt_backtest.json --timerange 20251101- --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0

# VWAP strategy backtest
freqtrade backtesting --strategy live_VwapCross --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/bt_backtest.json --timerange 20260310- --datadir /allah/freqtrade/user_data/data/binance --cache none --starting-balance 10000 --eps --fee 0

# ML Export Commands (Triple Barrier Labeling)
# Long-only
freqtrade backtesting --strategy TemaReversalLong --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/ml_export.json --timerange 20251201- --datadir /allah/freqtrade/user_data/data/binance --cache none --eps --fee 0

# Short-only
freqtrade backtesting --strategy TemaReversalShort --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/ml_export.json --timerange 20251201- --datadir /allah/freqtrade/user_data/data/binance --cache none --eps --fee 0

# Long + Short
freqtrade backtesting --strategy TemaReversalBoth --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/ml_export.json --timerange 20251201- --datadir /allah/freqtrade/user_data/data/binance --cache none --eps --fee 0
