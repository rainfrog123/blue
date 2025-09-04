# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Read 5s ETH/USDT futures data 
df = pd.read_feather('/allah/freqtrade/user_data/data/binance/futures/ETH_USDT_USDT-5s-futures.feather')
df.set_index('date', inplace=True)

# Filter for 8/1/2025
target_date = '2025-08-01'
df_day = df[df.index.date == pd.to_datetime(target_date).date()].copy()

print(f"Data shape for {target_date}: {df_day.shape}")
print(f"Time range: {df_day.index.min()} to {df_day.index.max()}")
print(df_day.head())

# Calculate ATR as percentage volatility
# Step 1: Calculate True Range
df_day['prev_close'] = df_day['close'].shift(1)
df_day['tr1'] = df_day['high'] - df_day['low']
df_day['tr2'] = abs(df_day['high'] - df_day['prev_close'])
df_day['tr3'] = abs(df_day['low'] - df_day['prev_close'])
df_day['true_range'] = df_day[['tr1', 'tr2', 'tr3']].max(axis=1)

# Step 2: Calculate ATR using rolling average
window = 23  # Standard ATR period
df_day['atr'] = df_day['true_range'].rolling(window=window).mean()

# Step 3: Convert to percentage
df_day['volatility_pct'] = (df_day['atr'] / df_day['close']) * 100

# Step 3: Remove NaN values from initial window
df_clean = df_day.dropna().copy()

print(f"Volatility stats for {target_date}:")
print(f"Mean volatility: {df_clean['volatility_pct'].mean():.4f}%")
print(f"Max volatility: {df_clean['volatility_pct'].max():.4f}%")
print(f"Min volatility: {df_clean['volatility_pct'].min():.4f}%")

# Plot volatility throughout the day
plt.figure(figsize=(15, 8))
plt.subplot(2, 1, 1)
plt.plot(df_clean.index, df_clean['close'], alpha=0.7, linewidth=0.8)
plt.title(f'ETH/USDT Price on {target_date}')
plt.ylabel('Price (USDT)')

plt.subplot(2, 1, 2)
plt.plot(df_clean.index, df_clean['volatility_pct'], color='red', alpha=0.8)
plt.title(f'ATR(14) Volatility (%) on {target_date}')
plt.ylabel('Volatility %')
plt.xlabel('Time')
plt.tight_layout()
plt.show()

print(f"\nHighest ATR volatility periods:")
high_vol = df_clean.nlargest(5, 'volatility_pct')[['close', 'atr', 'volatility_pct']]
print(high_vol)

# %%

# %%

