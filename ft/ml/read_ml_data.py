#%% Imports, Config & Load Data
import pandas as pd
import numpy as np
import os
from pathlib import Path
from sklearn.model_selection import train_test_split

ML_DATA_DIR = "/allah/freqtrade/user_data/data/binance/ml/"
STRATEGY_NAME = "TemaReversalLongFixed"
OUTPUT_DIR = Path("/allah/blue/ft/ml/processed")

files = sorted([f for f in os.listdir(ML_DATA_DIR) if f.endswith('.feather')], reverse=True)
print(f"Available ML export files ({len(files)} total):")
for f in files[:10]:
    print(f"  {f}")

strategy_files = [f for f in files if STRATEGY_NAME in f]
if strategy_files:
    latest_file = strategy_files[0]
    print(f"\nLoading: {latest_file}")
    df = pd.read_feather(ML_DATA_DIR + latest_file)
    print(f"Shape: {df.shape}")
else:
    raise FileNotFoundError(f"No files found for strategy: {STRATEGY_NAME}")

#%% Data Exploration
print("\n=== DATAFRAME INFO ===")
print(f"Rows: {len(df):,}")
print(f"Columns: {len(df.columns)}")
print(f"Date range: {df['date'].min()} to {df['date'].max()}")
print(f"Memory: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

print("\n=== COLUMNS ===")
for col in df.columns:
    dtype = df[col].dtype
    non_null = df[col].notna().sum()
    print(f"  {col:<20} {str(dtype):<15} ({non_null:,} non-null)")
# print the first 10 rows of the dataframe that with trades with dataframe 
df_trades = df[df['label'].notna()].copy()
print(df_trades.head(10))
print("\n=== LABEL DISTRIBUTION ===")
label_counts = df['label'].value_counts()
total_labeled = label_counts.sum()
for label, count in label_counts.items():
    print(f"  {label}: {count:,} ({count/total_labeled*100:.1f}%)")

print("\n=== EXIT REASONS ===")
print(df['exit_reason'].value_counts())

print("\n=== FEATURE STATISTICS ===")
print(df[['tema', 'atr', 'risk', 'close', 'volume']].describe())

df_trades = df[df['label'].notna()].copy()
print(f"\n=== TRADE DATA ===")
print(f"Total trades: {len(df_trades):,}")
print(f"Winners: {(df_trades['is_winner'] == 1).sum():,}")
print(f"Losers: {(df_trades['is_winner'] == 0).sum():,}")

#%% Prepare, Split & Save ML Data
feature_columns = [
    'tema', 'tema_prev', 
    'atr', 'risk',
    'close', 'open', 'high', 'low', 'volume',
    'close_1m', 'open_1m', 'high_1m', 'low_1m', 'volume_1m',
]

X = df_trades[feature_columns].values
y = df_trades['is_winner'].values

print("\n=== PREPARING ML DATA ===")
print(f"X shape: {X.shape}")
print(f"y shape: {y.shape}")
print(f"y distribution: {np.bincount(y.astype(int))}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, shuffle=False
)

print(f"\n=== TRAIN/TEST SPLIT ===")
print(f"Train: {len(X_train):,} samples ({y_train.mean()*100:.1f}% win rate)")
print(f"Test: {len(X_test):,} samples ({y_test.mean()*100:.1f}% win rate)")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
np.save(OUTPUT_DIR / "X_train.npy", X_train)
np.save(OUTPUT_DIR / "X_test.npy", X_test)
np.save(OUTPUT_DIR / "y_train.npy", y_train)
np.save(OUTPUT_DIR / "y_test.npy", y_test)
with open(OUTPUT_DIR / "feature_names.txt", "w") as f:
    f.write("\n".join(feature_columns))

print(f"\n=== SAVED TO {OUTPUT_DIR} ===")
print(f"  X_train.npy: {X_train.shape}")
print(f"  X_test.npy: {X_test.shape}")
print(f"  y_train.npy: {y_train.shape}")
print(f"  y_test.npy: {y_test.shape}")
print(f"  feature_names.txt")

print("\n=== SANITY CHECK ===")
print(f"Any NaN in X_train: {np.isnan(X_train).any()}")
print(f"Any NaN in y_train: {np.isnan(y_train).any()}")
print(f"X_train range: [{X_train.min():.4f}, {X_train.max():.4f}]")
print(f"y unique values: {np.unique(y)}")
