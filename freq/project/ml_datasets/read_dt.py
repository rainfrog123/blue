# %%
import pandas as pd
df = pd.read_feather('/allah/data/ml/TemaSlope-ETH_USDT_USDT-1224-1550.feather')
df
# %%
df.describe()

# %%
df.info()

# %%
df.head()

# %%
df.tail()

# %% rows that with profit_ratio not null
trades = df[df['profit_ratio'].notna()]
trades.head()

# %% Dataset Overview
print(f'Shape: {df.shape[0]:,} rows x {df.shape[1]} columns')
print(f'Date range: {df["date"].min()} to {df["date"].max()}')
print(f'Columns: {df.columns.tolist()}')

# %% Trade Statistics
print(f'Total candles: {len(df):,}')
print(f'Trade entries: {len(trades):,}')
print(f'Trade ratio: {len(trades)/len(df)*100:.4f}%')

# %% Profit Analysis
print(f'Win rate: {(trades["profit_ratio"] > 0).mean()*100:.2f}%')
print(f'Total profit: {trades["profit_ratio"].sum()*100:.4f}%')
print(f'Avg profit per trade: {trades["profit_ratio"].mean()*100:.4f}%')
print(f'Max profit: {trades["profit_ratio"].max()*100:.4f}%')
print(f'Max loss: {trades["profit_ratio"].min()*100:.4f}%')

# %% Trade Duration
valid_trades = trades[trades['close_timestamp'].notna() & trades['open_timestamp'].notna()]
duration = (valid_trades['close_timestamp'] - valid_trades['open_timestamp']) / 1000
print(f'Avg duration: {duration.mean():.1f} seconds')
print(f'Min duration: {duration.min():.1f} seconds')
print(f'Max duration: {duration.max():.1f} seconds')

# %% Leverage & Direction
print(f'Leverage used: {trades["leverage"].dropna().unique()}')
print(f'Long trades: {len(trades[trades["is_short"] == False])}')
print(f'Short trades: {len(trades[trades["is_short"] == True])}')

# %% Profit Distribution
trades['profit_ratio'].hist(bins=50)

# %% df exit reason 
df['exit_reason'].value_counts()
# %%
