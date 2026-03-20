# Binance Perpetual USDT Market Maker

Market making bot for Binance Perpetual futures using Hummingbot framework.

## Files

| File | Description |
|------|-------------|
| `binance_perp_mm.py` | Main strategy script (Hummingbot V2) |
| `config_binance_perp_mm.yml` | Strategy configuration |
| `conf_binance_perpetual.yml` | Exchange connector credentials |
| `setup.sh` | Setup script to install and configure |
| `run_mm.py` | Standalone runner (no CLI needed) |

## Quick Start

### Option 1: Using Hummingbot CLI

```bash
# Run setup
chmod +x setup.sh && ./setup.sh

# Start Hummingbot
cd /allah/hummingbot
./start

# In Hummingbot CLI
>>> connect binance_perpetual
>>> start --script binance_perp_mm.py
```

### Option 2: Standalone Python

```bash
# Install hummingbot first
cd /allah/hummingbot
pip install -e .

# Run directly
python /allah/blue/ft/hummingbot/run_mm.py
```

## Configuration

Edit `config_binance_perp_mm.yml`:

```yaml
# Trading pair
trading_pair: BTC-USDT

# Position settings
leverage: 10
order_amount: 0.001  # BTC per level

# Spread settings (0.0005 = 0.05%)
bid_spread: 0.0005
ask_spread: 0.0005

# Multi-level orders
order_levels: 3
order_level_spread: 0.0003
order_level_amount: 1.0

# Risk management
max_position_size: 0.1
```

## Strategy Overview

The market maker:

1. Places limit orders on both sides of the order book
2. Uses multiple price levels with increasing spreads
3. Refreshes orders every N seconds
4. Manages position limits automatically
5. Supports configurable leverage (up to 125x)

### Order Placement

```
SELL L2: 0.001 BTC @ mid + 0.11%
SELL L1: 0.001 BTC @ mid + 0.08%
SELL L0: 0.001 BTC @ mid + 0.05%
          --- MID PRICE ---
BUY L0:  0.001 BTC @ mid - 0.05%
BUY L1:  0.001 BTC @ mid - 0.08%
BUY L2:  0.001 BTC @ mid - 0.11%
```

## Risk Warning

- This is a market making strategy that can lose money
- Perpetual futures involve leverage and liquidation risk
- Start with small amounts to test
- Monitor positions and PnL closely
- API keys have trading permissions - keep them secure

## Credentials

API credentials are loaded from `/allah/blue/cred.json`:

```json
{
  "binance": {
    "api_key": "...",
    "api_secret": "..."
  }
}
```
