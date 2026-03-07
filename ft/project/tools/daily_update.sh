#!/bin/bash
#
# Daily data update script
# - Updates freqtrade virtual environment
# - Downloads latest daily trade data
# - Converts to feather format for freqtrade
# - Downloads standard OHLCV data via freqtrade
#

set -e

# Paths
FREQTRADE_DIR="/allah/freqtrade"
TOOLS_DIR="/allah/blue/ft/project/tools"

echo "=== Daily Data Update ==="
echo "Started at: $(date)"
echo ""

# Deactivate any active virtual environment
unset VIRTUAL_ENV

# Update freqtrade environment
cd "$FREQTRADE_DIR"

current_branch=$(git branch --show-current)

for branch in $(git branch | sed 's/^[* ]*//'); do
    echo "Processing branch: $branch"
    git checkout "$branch"
    echo "Y" | ./setup.sh -u
done

git checkout "$current_branch"
pip install fastparquet matplotlib

# Download daily trades
echo ""
echo "=== Downloading Daily Trades ==="
cd "$TOOLS_DIR"
python3 "$TOOLS_DIR/historical/binance_daily.py"

# Convert to feather
echo ""
echo "=== Converting to Feather ==="
python3 "$TOOLS_DIR/converters/parquet_to_feather.py"

# Download standard OHLCV data
echo ""
echo "=== Downloading OHLCV Data ==="
freqtrade download-data \
    --userdir /allah/blue/ft/project/user_data \
    --config /allah/blue/ft/project/user_data/config/download_proxy.json \
    --timerange 20251201- \
    --timeframes 1m 3m 5m 15m 30m 1h 4h \
    --datadir /allah/freqtrade/user_data/data/binance

echo ""
echo "=== Daily Update Complete ==="
echo "Finished at: $(date)"

