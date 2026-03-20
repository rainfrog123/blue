#!/bin/bash
# Setup script for Binance Perpetual Market Maker

set -e

HUMMINGBOT_DIR="/allah/hummingbot"
FT_HUMMINGBOT_DIR="/allah/blue/ft/hummingbot"

echo "=== Binance Perpetual Market Maker Setup ==="

# Create necessary directories
mkdir -p "$HUMMINGBOT_DIR/conf/connectors"
mkdir -p "$HUMMINGBOT_DIR/conf/strategies"
mkdir -p "$HUMMINGBOT_DIR/scripts"

# Copy connector config
echo "Copying connector configuration..."
cp "$FT_HUMMINGBOT_DIR/conf_binance_perpetual.yml" "$HUMMINGBOT_DIR/conf/connectors/binance_perpetual.yml"

# Copy strategy script
echo "Copying strategy script..."
cp "$FT_HUMMINGBOT_DIR/binance_perp_mm.py" "$HUMMINGBOT_DIR/scripts/binance_perp_mm.py"

# Copy strategy config
echo "Copying strategy configuration..."
cp "$FT_HUMMINGBOT_DIR/config_binance_perp_mm.yml" "$HUMMINGBOT_DIR/conf/strategies/config_binance_perp_mm.yml"

# Install dependencies
echo "Installing Hummingbot dependencies..."
cd "$HUMMINGBOT_DIR"

# Check if conda is available
if command -v conda &> /dev/null; then
    echo "Using conda environment..."
    conda env create -f setup/environment.yml 2>/dev/null || conda env update -f setup/environment.yml
    conda activate hummingbot
else
    echo "Using pip installation..."
    pip install -e . --quiet
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the market maker:"
echo "  cd $HUMMINGBOT_DIR"
echo "  ./start"
echo ""
echo "Then in Hummingbot CLI:"
echo "  >>> connect binance_perpetual"
echo "  >>> start --script binance_perp_mm.py"
echo ""
