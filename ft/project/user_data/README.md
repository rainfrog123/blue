# FreqTrade 5-Second Trading Project

This project contains trading strategies and configurations for FreqTrade with 5-second timeframe support.

## Current Implementation

The project uses a custom DataProvider located in `/allah/freqtrade/freqtrade/data/custom_dataprovider_5s.py` that reads 5-second candles from a local SQLite database at `/allah/data/tv_candles.db`.

## Available Strategies

- `Test5sStrategy.py` - Simple volume-based strategy for testing 5s timeframe
- `TrendRevATR.py` - ATR-based trend reversal strategy
- `FastTEMA_ReversalTrader.py` - TEMA-based reversal trading strategy  
- `FreqAIDynamicClassifierStrategy.py` - AI-based classification strategy
- `TrendReversalLabelingStrategy.py` - Strategy for labeling trend reversals

## Configuration Files

- `config_test_5s.json` - Test configuration for 5s trading
- `config_prod.json` - Production configuration
- `config_debug.json` - Debug configuration with verbose logging
- `config_freqai.json` - FreqAI configuration

## Scripts

- `fetch_binance_trades.py` - Fetches trade data from Binance
- `integrate_custom_candles.py` - Integration utilities for custom candle data

## Usage

Run FreqTrade with 5s strategies:

```bash
/allah/freqtrade/.venv/bin/python3 /allah/freqtrade/freqtrade/main.py trade \
  --strategy Test5sStrategy \
  --config user_data/config_test_5s.json \
  --userdir /allah/stuff/freq/project_2/user_data
```

## Data Requirements

Ensure the SQLite database `/allah/data/tv_candles.db` contains 5-second candle data with the proper schema expected by the CustomDataProvider5s class 