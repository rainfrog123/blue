# Hyperopt Commands

# Find best ATR SL multiplier (k), TP is auto 2x SL
freqtrade hyperopt --strategy bt_TemaSlope --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/bt_backtest.json --timerange 1761501600-1761505200 --datadir /allah/freqtrade/user_data/data/binance --hyperopt-loss SharpeHyperOptLossDaily --spaces sell -e 100 --fee 0

freqtrade hyperopt --strategy live_VwapCross --userdir /allah/blue/ft/user_data --config /allah/blue/ft/user_data/config/bt_backtest.json --timerange 20260310- --datadir /allah/freqtrade/user_data/data/binance --hyperopt-loss SharpeHyperOptLossDaily --spaces buy sell -e 50 --fee 0 2>&1
