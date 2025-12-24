# %% Block 1: Data Loading
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
from pathlib import Path
import talib as ta

# Load dataset
dataset_path = "TEMAReversal_MLStrategy_ml_dataset.feather"
summary_path = "TEMAReversal_MLStrategy_ml_dataset_summary.json"
df = pd.read_feather(dataset_path)
json_data = json.load(open(summary_path))

# Create previous trade state as features (avoid look-ahead bias)
trade_info_columns = [
    'trade_id', 'trade_open', 'pair_trade', 'stake_amount', 'max_stake_amount', 
    'amount', 'open_rate', 'close_rate', 'fee_open', 'fee_close', 
    'trade_duration', 'profit_ratio', 'profit_abs', 'exit_reason', 
    'initial_stop_loss_abs', 'initial_stop_loss_ratio', 'stop_loss_abs', 
    'stop_loss_ratio', 'min_rate', 'max_rate', 'is_open', 'leverage', 
    'is_short', 'open_timestamp', 'close_timestamp', 'orders', 'funding_fees'
]

if 'trade_open' in df.columns:
    mask = df['trade_open'] == True
    cols = [c for c in trade_info_columns if c in df.columns]
    if cols and mask.any():
        # Vectorized: copy trade_open=True rows' trade info to previous rows
        shifted_mask = mask.shift(-1).fillna(False)
        df.loc[shifted_mask, cols] = df.loc[mask, cols].values
        # Set all trade_open=True rows' trade info to NaN
        df.loc[mask, cols] = np.nan
# %%
with pd.option_context('display.max_columns', None):
    display(df.iloc[87:90])
    # df.iloc[88].orders display
    display(df.iloc[88].orders)

# %%
# %% Block 2: Feature Engineering
# Base indicators
df['EMA_20'] = ta.EMA(df['close'], timeperiod=20)
df['EMA_50'] = ta.EMA(df['close'], timeperiod=50)
df['RSI'] = ta.RSI(df['close'], timeperiod=14)
df['ATR'] = ta.ATR(df['high'], df['low'], df['close'], timeperiod=14)
df['MACD'], df['MACD_signal'], df['MACD_hist'] = ta.MACD(df['close'])
df['CCI'] = ta.CCI(df['high'], df['low'], df['close'], timeperiod=14)
df['BBANDS_upper'], df['BBANDS_middle'], df['BBANDS_lower'] = ta.BBANDS(df['close'])
df['OBV'] = ta.OBV(df['close'], df['volume'])

# Trend features
df['ema_20_slope'] = df['EMA_20'].diff(5) / df['EMA_20'].shift(5)
df['ema_50_slope'] = df['EMA_50'].diff(10) / df['EMA_50'].shift(10)
df['roc_5'] = ta.ROC(df['close'], timeperiod=5)
df['roc_10'] = ta.ROC(df['close'], timeperiod=10)
df['price_vs_ema20'] = (df['close'] - df['EMA_20']) / df['ATR']
df['price_vs_ema50'] = (df['close'] - df['EMA_50']) / df['ATR']

# Momentum features
df['rsi_centered'] = (df['RSI'] - 50) / 50
df['cci_norm'] = df['CCI'] / 100
df['macd_norm'] = df['MACD'] / df['close']
df['price_momentum'] = df['close'].diff(3) / df['close'].shift(3)
df['price_acceleration'] = df['close'].diff().diff()
df['rsi_momentum'] = df['RSI'].diff(3)

# Volatility features
df['atr_ratio'] = df['ATR'] / df['close']
df['bb_width'] = (df['BBANDS_upper'] - df['BBANDS_lower']) / df['BBANDS_middle']
df['volatility_5'] = df['close'].rolling(5).std() / df['close']
df['high_low_range'] = (df['high'] - df['low']) / df['close']

# Structure features
df['higher_high'] = (df['high'] > df['high'].shift(1)).astype(int)
df['lower_low'] = (df['low'] < df['low'].shift(1)).astype(int)
df['close_vs_high'] = (df['close'] - df['high']) / df['ATR']
df['close_vs_low'] = (df['close'] - df['low']) / df['ATR']
df['body_size'] = (df['close'] - df['open']) / df['ATR']

# Order flow features
df['volume_spike'] = df['volume'] / df['volume'].rolling(20).mean()
df['volume_trend'] = df['volume'].diff(3) / df['volume'].shift(3)
df['obv_momentum'] = df['OBV'].diff(5) / df['volume']
df['price_volume'] = df['price_momentum'] * df['volume_spike']

# Multi-timeframe features
df['ema_alignment'] = np.where(df['EMA_20'] > df['EMA_50'], 1, -1)
df['trend_strength'] = (df['EMA_20'] - df['EMA_50']) / df['ATR']
df['price_position'] = np.where(df['close'] > df['EMA_20'], 1, -1)

# Side column
if 'trend_up' in df.columns:
    df['side'] = np.where(df['trend_up'] == True, 1, -1)
else:
    df['side'] = 0

# Feature flipping
directional_features = [
    'ema_20_slope', 'ema_50_slope', 'roc_5', 'roc_10', 
    'price_vs_ema20', 'price_vs_ema50',
    'rsi_centered', 'cci_norm', 'macd_norm', 'price_momentum',
    'price_acceleration', 'rsi_momentum',
    'close_vs_high', 'close_vs_low', 'body_size',
    'volume_trend', 'obv_momentum', 'price_volume',
    'ema_alignment', 'trend_strength', 'price_position'
]

for feature in directional_features:
    df[f'norm_{feature}'] = df['side'] * df[feature]

non_directional_features = [
    'atr_ratio', 'bb_width', 'volatility_5', 'high_low_range',
    'volume_spike', 'RSI', 'ATR'
]

# %%