# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Read 5s ETH/USDT futures data 
df = pd.read_feather('/allah/freqtrade/user_data/data/binance/futures/ETH_USDT_USDT-5s-futures.feather')
df.set_index('date', inplace=True)

# Filter for 8/1/2025
target_date = '2025-09-01'
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
window = 33  # Standard ATR period
df_day['atr'] = df_day['true_range'].rolling(window=window).mean()

# Step 3: Convert to percentage
df_day['volatility_pct'] = (df_day['atr'] / df_day['close']) * 100

# Step 3: Remove NaN values from initial window
df_clean = df_day.dropna().copy()

print(f"Volatility stats for {target_date}:")
print(f"Mean volatility: {df_clean['volatility_pct'].mean():.4f}%")
print(f"Max volatility: {df_clean['volatility_pct'].max():.4f}%")
print(f"Min volatility: {df_clean['volatility_pct'].min():.4f}%")

# Plot volatility for every 2-hour period
from matplotlib.ticker import FuncFormatter

def percent_formatter(x, pos):
    return f'{x:.3f}%'

# Show only last 30 minutes (23:30-24:00)
start_time = pd.to_datetime(f'{target_date} 23:30:00', utc=True)
end_time = pd.to_datetime(f'{target_date} 23:59:59', utc=True)
mask = (df_clean.index >= start_time) & (df_clean.index <= end_time)
df_period = df_clean[mask]

if len(df_period) > 0:
    plt.figure(figsize=(12, 8))
    
    plt.subplot(2, 1, 1)
    plt.plot(df_period.index, df_period['close'], alpha=0.7, linewidth=1)
    plt.title('ETH/USDT Price (23:30 - 24:00)')
    plt.ylabel('Price (USDT)')
    plt.grid(True, alpha=0.3)
    
    plt.subplot(2, 1, 2)
    plt.plot(df_period.index, df_period['volatility_pct'], color='red', alpha=0.8, linewidth=1)
    plt.title('ATR Volatility (23:30 - 24:00)')
    plt.ylabel('Volatility')
    plt.xlabel('Time')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(percent_formatter))
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()
    
    # Print stats for this period
    print(f"\nPeriod 23:30-24:00:")
    print(f"  Mean volatility: {df_period['volatility_pct'].mean():.4f}%")
    print(f"  Max volatility: {df_period['volatility_pct'].max():.4f}%")
    print(f"  Data points: {len(df_period)}")

print(f"\nHighest ATR volatility periods:")
high_vol = df_clean.nlargest(5, 'volatility_pct')[['close', 'atr', 'volatility_pct']]
print(high_vol)

# %%

# %%

