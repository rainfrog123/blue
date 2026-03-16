# %% [CELL 1: Load Dataset]
import pandas as pd
import numpy as np
import talib as ta

df = pd.read_feather('/allah/data/ml/TemaSlope-ETH_USDT_USDT-1224-1550.feather')
print(f"Dataset: {df.shape}, Trades: {df['profit_ratio'].notna().sum()}")
print(f"Exit reasons:\n{df['exit_reason'].value_counts()}")

# %% [CELL 2: Feature Engineering]
df_features = df.copy()
o, h, l, c, v = df['open'], df['high'], df['low'], df['close'], df['volume']

# === STRATEGY FEATURES (from dataset) ===
# tema, tema_slope already exist

# === TICK MICROSTRUCTURE (use existing counts) ===
df_features['tick_total'] = df['open_count'] + df['high_count'] + df['low_count'] + df['close_count']
df_features['tick_imbalance'] = (df['high_count'] - df['low_count']) / (df_features['tick_total'] + 1e-10)
df_features['tick_activity'] = df_features['tick_total'] / (df_features['tick_total'].rolling(12).mean() + 1e-10)
df_features['tick_concentration'] = df['max_count'] / (df_features['tick_total'] + 1e-10)

# === PRICE MOMENTUM (very short-term for 5s bars) ===
df_features['ret_1'] = c.pct_change(1) * 100
df_features['ret_3'] = c.pct_change(3) * 100  # 15 seconds
df_features['ret_6'] = c.pct_change(6) * 100  # 30 seconds
df_features['ret_12'] = c.pct_change(12) * 100  # 1 minute
df_features['ret_24'] = c.pct_change(24) * 100  # 2 minutes

# Momentum acceleration
df_features['mom_accel'] = df_features['ret_3'] - df_features['ret_3'].shift(3)
df_features['mom_consistency'] = (df_features['ret_1'] > 0).rolling(6).sum() / 6  # % positive bars

# === TEMA DYNAMICS ===
df_features['tema_slope_accel'] = df['tema_slope'].diff(1)
df_features['tema_slope_ma'] = df['tema_slope'].rolling(6).mean()
df_features['tema_slope_std'] = df['tema_slope'].rolling(12).std()
df_features['tema_slope_z'] = (df['tema_slope'] - df_features['tema_slope_ma']) / (df_features['tema_slope_std'] + 1e-10)
df_features['price_vs_tema'] = (c - df['tema']) / df['tema'] * 100

# === VOLATILITY (ultra short-term) ===
df_features['range_pct'] = (h - l) / c * 100
df_features['range_ma6'] = df_features['range_pct'].rolling(6).mean()
df_features['range_ratio'] = df_features['range_pct'] / (df_features['range_ma6'] + 1e-10)
df_features['atr_6'] = ta.ATR(h, l, c, timeperiod=6)
df_features['natr_6'] = ta.NATR(h, l, c, timeperiod=6)

# Volatility regime
df_features['vol_expanding'] = (df_features['range_pct'] > df_features['range_pct'].rolling(12).mean()).astype(int)

# === VOLUME DYNAMICS ===
df_features['vol_ma6'] = v.rolling(6).mean()
df_features['vol_ma24'] = v.rolling(24).mean()
df_features['vol_ratio'] = v / (df_features['vol_ma6'] + 1e-10)
df_features['vol_trend'] = df_features['vol_ma6'] / (df_features['vol_ma24'] + 1e-10)
df_features['vol_price_corr'] = df_features['ret_1'].rolling(12).corr(v)

# === CANDLE STRUCTURE ===
df_features['body_pct'] = (c - o) / o * 100
df_features['body_abs'] = abs(c - o) / (h - l + 1e-10)  # body/range ratio
df_features['upper_wick'] = (h - np.maximum(o, c)) / (h - l + 1e-10)
df_features['lower_wick'] = (np.minimum(o, c) - l) / (h - l + 1e-10)
df_features['close_pos'] = (c - l) / (h - l + 1e-10)

# Consecutive candle patterns
df_features['consec_up'] = (df_features['body_pct'] > 0).rolling(6).sum()
df_features['consec_down'] = (df_features['body_pct'] < 0).rolling(6).sum()

# === RSI (short period) ===
df_features['rsi_6'] = ta.RSI(c, timeperiod=6)
df_features['rsi_slope'] = df_features['rsi_6'].diff(3)

# === PRICE LEVELS ===
df_features['dist_from_high_12'] = (c - h.rolling(12).max()) / c * 100
df_features['dist_from_low_12'] = (c - l.rolling(12).min()) / c * 100
df_features['price_position'] = (c - l.rolling(24).min()) / (h.rolling(24).max() - l.rolling(24).min() + 1e-10)

new_cols = [col for col in df_features.columns if col not in df.columns]
print(f"Features added: {len(new_cols)}")

# %% [CELL 3: Binary Labels & Filter Trades]
# Label: 1 if exit_reason is 'roi', 0 otherwise (stop_loss, timeout, force_exit)
df_features = df_features[df_features['profit_ratio'].notna()].copy()
df_features['is_profitable'] = (df_features['exit_reason'] == 'roi').astype(int)

wins = (df_features['is_profitable'] == 1).sum()
losses = (df_features['is_profitable'] == 0).sum()
print(f"Trades: {len(df_features)} (ROI: {wins} [{wins/len(df_features)*100:.1f}%], Other: {losses})")

# %% [CELL 4: Feature Scaling]
from sklearn.preprocessing import StandardScaler

feature_cols = [
    # Strategy features
    'tema', 'tema_slope',
    # Tick microstructure (4)
    'tick_total', 'tick_imbalance', 'tick_activity', 'tick_concentration',
    # Price momentum (7)
    'ret_1', 'ret_3', 'ret_6', 'ret_12', 'ret_24', 'mom_accel', 'mom_consistency',
    # TEMA dynamics (5)
    'tema_slope_accel', 'tema_slope_ma', 'tema_slope_std', 'tema_slope_z', 'price_vs_tema',
    # Volatility (6)
    'range_pct', 'range_ma6', 'range_ratio', 'atr_6', 'natr_6', 'vol_expanding',
    # Volume dynamics (5)
    'vol_ma6', 'vol_ma24', 'vol_ratio', 'vol_trend', 'vol_price_corr',
    # Candle structure (7)
    'body_pct', 'body_abs', 'upper_wick', 'lower_wick', 'close_pos', 'consec_up', 'consec_down',
    # RSI (2)
    'rsi_6', 'rsi_slope',
    # Price levels (3)
    'dist_from_high_12', 'dist_from_low_12', 'price_position'
]

df_scaled = df_features.copy()
df_scaled[feature_cols] = df_scaled[feature_cols].ffill().bfill()

# Before scaling stats
print(f"=== BEFORE SCALING ({len(feature_cols)} features) ===")
before_stats = df_scaled[feature_cols].describe().T[['mean', 'std', 'min', 'max']]
print(before_stats.to_string())

scaler = StandardScaler()
df_scaled[feature_cols] = scaler.fit_transform(df_scaled[feature_cols])

# After scaling stats
print(f"\n=== AFTER SCALING ===")
after_stats = df_scaled[feature_cols].describe().T[['mean', 'std', 'min', 'max']]
print(after_stats.to_string())

# %% [CELL 5: Data Diagnostics]
y = df_scaled['is_profitable']
print("=== DATA DIAGNOSTICS ===")
print(f"Class distribution: {y.value_counts().to_dict()}, Win rate: {y.mean():.3f}")

corrs = df_scaled[feature_cols + ['is_profitable']].corr()['is_profitable'].drop('is_profitable')
print(f"\nTop 10 correlations with target:")
print(corrs.abs().sort_values(ascending=False).head(10))

# %% [CELL 6: Train Models]
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb
import lightgbm as lgb

X = df_scaled[feature_cols]
y = df_scaled['is_profitable']

split_idx = int(len(X) * 0.8)
X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

scale_pos = (y_train == 0).sum() / (y_train == 1).sum()
print(f"Train: {len(X_train)}, Test: {len(X_test)}, scale_pos_weight: {scale_pos:.2f}")

models = {
    'RandomForest': RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1, class_weight='balanced'),
    'GradientBoost': GradientBoostingClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42),
    'XGBoost': xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric='logloss', scale_pos_weight=scale_pos),
    'LightGBM': lgb.LGBMClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, n_jobs=-1, verbose=-1, is_unbalance=True),
    'LogisticReg': LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'),
    'NeuralNet': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42, early_stopping=True)
}

results = []
for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
    results.append({
        'Model': name,
        'Accuracy': accuracy_score(y_test, y_pred),
        'Precision': precision_score(y_test, y_pred, zero_division=0),
        'Recall': recall_score(y_test, y_pred, zero_division=0),
        'F1': f1_score(y_test, y_pred, zero_division=0),
        'ROC-AUC': roc_auc_score(y_test, y_proba) if y_proba is not None else 0
    })

results_df = pd.DataFrame(results).sort_values('F1', ascending=False)
display(results_df)

# Best model details
best_name = results_df.iloc[0]['Model']
best_model = models[best_name]
y_pred_best = best_model.predict(X_test)
print(f"\nBest: {best_name}")
print(f"Pred dist: {pd.Series(y_pred_best).value_counts().to_dict()}, Actual: {y_test.value_counts().to_dict()}")

if hasattr(best_model, 'feature_importances_'):
    imp_df = pd.DataFrame({'Feature': feature_cols, 'Importance': best_model.feature_importances_})
    print(f"\nTop 15 Features:")
    display(imp_df.sort_values('Importance', ascending=False).head(15))

# %%
