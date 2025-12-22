# %% [CELL 1: Load Dataset]
import pandas as pd
import numpy as np
import talib as ta

df = pd.read_feather('/allah/data/ml/atr_tp-1124-2038.feather')
print(f"Dataset: {df.shape}, Trades: {df['profit_ratio'].notna().sum()}")

# %% [CELL 2: Feature Engineering]
df_features = df.copy()
o, h, l, c, v = df['open'], df['high'], df['low'], df['close'], df['volume']

# === PRICE ACTION FEATURES (15) ===
df_features['body'] = (c - o) / o * 100  # body size %
df_features['body_abs'] = abs(c - o) / o * 100
df_features['upper_wick'] = (h - np.maximum(o, c)) / c * 100
df_features['lower_wick'] = (np.minimum(o, c) - l) / c * 100
df_features['range'] = (h - l) / c * 100
df_features['body_ratio'] = df_features['body_abs'] / (df_features['range'] + 1e-10)  # body/range
df_features['upper_wick_ratio'] = df_features['upper_wick'] / (df_features['range'] + 1e-10)
df_features['lower_wick_ratio'] = df_features['lower_wick'] / (df_features['range'] + 1e-10)
df_features['close_pos'] = (c - l) / (h - l + 1e-10)  # where close is in range [0,1]
df_features['gap'] = (o - c.shift(1)) / c.shift(1) * 100  # gap from prev close
df_features['ret_1'] = c.pct_change(1) * 100  # 1-bar return
df_features['ret_3'] = c.pct_change(3) * 100
df_features['ret_5'] = c.pct_change(5) * 100
df_features['high_break'] = (h > h.shift(1)).astype(int)  # broke prev high
df_features['low_break'] = (l < l.shift(1)).astype(int)   # broke prev low

# === VOLATILITY REGIME (10) ===
df_features['atr_7'] = ta.ATR(h, l, c, timeperiod=7)
df_features['atr_14'] = ta.ATR(h, l, c, timeperiod=14)
df_features['atr_ratio'] = df_features['atr_7'] / (df_features['atr_14'] + 1e-10)  # vol expansion
df_features['range_ma'] = df_features['range'].rolling(10).mean()
df_features['range_std'] = df_features['range'].rolling(10).std()
df_features['vol_regime'] = df_features['range'] / (df_features['range_ma'] + 1e-10)  # current vs avg
df_features['bb_width'] = (ta.BBANDS(c, 12)[0] - ta.BBANDS(c, 12)[2]) / c * 100  # BB width %
df_features['vol_ma'] = v.rolling(10).mean()
df_features['vol_ratio'] = v / (df_features['vol_ma'] + 1e-10)  # volume spike
df_features['natr'] = ta.NATR(h, l, c, timeperiod=7)  # normalized ATR

# === CANDLE PATTERNS (15) ===
df_features['cdl_doji'] = ta.CDLDOJI(o, h, l, c) / 100
df_features['cdl_hammer'] = ta.CDLHAMMER(o, h, l, c) / 100
df_features['cdl_engulf'] = ta.CDLENGULFING(o, h, l, c) / 100
df_features['cdl_morning'] = ta.CDLMORNINGSTAR(o, h, l, c) / 100
df_features['cdl_evening'] = ta.CDLEVENINGSTAR(o, h, l, c) / 100
df_features['cdl_3white'] = ta.CDL3WHITESOLDIERS(o, h, l, c) / 100
df_features['cdl_3black'] = ta.CDL3BLACKCROWS(o, h, l, c) / 100
df_features['cdl_harami'] = ta.CDLHARAMI(o, h, l, c) / 100
df_features['cdl_piercing'] = ta.CDLPIERCING(o, h, l, c) / 100
df_features['cdl_darkcloud'] = ta.CDLDARKCLOUDCOVER(o, h, l, c) / 100
df_features['cdl_shooting'] = ta.CDLSHOOTINGSTAR(o, h, l, c) / 100
df_features['cdl_invhammer'] = ta.CDLINVERTEDHAMMER(o, h, l, c) / 100
df_features['cdl_marubozu'] = ta.CDLMARUBOZU(o, h, l, c) / 100
df_features['cdl_spinning'] = ta.CDLSPINNINGTOP(o, h, l, c) / 100
df_features['cdl_hangman'] = ta.CDLHANGINGMAN(o, h, l, c) / 100

# === MOMENTUM & TREND (12) ===
df_features['rsi_7'] = ta.RSI(c, timeperiod=7)
df_features['rsi_14'] = ta.RSI(c, timeperiod=14)
df_features['rsi_slope'] = df_features['rsi_7'].diff(3)  # RSI momentum
df_features['macd'], df_features['macd_sig'], df_features['macd_hist'] = ta.MACD(c, 6, 13, 5)
df_features['ema_5'] = ta.EMA(c, 5)
df_features['ema_12'] = ta.EMA(c, 12)
df_features['ema_cross'] = (df_features['ema_5'] > df_features['ema_12']).astype(int)
df_features['price_vs_ema5'] = (c - df_features['ema_5']) / df_features['ema_5'] * 100
df_features['price_vs_ema12'] = (c - df_features['ema_12']) / df_features['ema_12'] * 100
df_features['adx'] = ta.ADX(h, l, c, timeperiod=7)
df_features['plus_di'] = ta.PLUS_DI(h, l, c, timeperiod=7)
df_features['minus_di'] = ta.MINUS_DI(h, l, c, timeperiod=7)

# === OSCILLATORS (8) ===
df_features['stoch_k'], df_features['stoch_d'] = ta.STOCH(h, l, c, 7, 3, 3)
df_features['cci'] = ta.CCI(h, l, c, timeperiod=7)
df_features['willr'] = ta.WILLR(h, l, c, timeperiod=7)
df_features['mfi'] = ta.MFI(h, l, c, v, timeperiod=7)
df_features['obv'] = ta.OBV(c, v)
df_features['obv_slope'] = df_features['obv'].diff(5)
df_features['cmo'] = ta.CMO(c, timeperiod=7)
df_features['roc'] = ta.ROC(c, timeperiod=5)

new_cols = [col for col in df_features.columns if col not in df.columns]
print(f"Features added: {len(new_cols)}")

# %% [CELL 3: Binary Labels & Filter Trades]
df_features['is_profitable'] = (df_features['profit_ratio'] > 0).astype(int)
df_features = df_features[df_features['profit_ratio'].notna()].copy()

wins = (df_features['is_profitable'] == 1).sum()
losses = (df_features['is_profitable'] == 0).sum()
print(f"Trades: {len(df_features)} (Win: {wins} [{wins/len(df_features)*100:.1f}%], Loss: {losses})")

# %% [CELL 4: Feature Scaling]
from sklearn.preprocessing import StandardScaler

feature_cols = [
    # Price action (15)
    'body', 'body_abs', 'upper_wick', 'lower_wick', 'range', 'body_ratio',
    'upper_wick_ratio', 'lower_wick_ratio', 'close_pos', 'gap',
    'ret_1', 'ret_3', 'ret_5', 'high_break', 'low_break',
    # Volatility (10)
    'atr_7', 'atr_14', 'atr_ratio', 'range_ma', 'range_std', 'vol_regime',
    'bb_width', 'vol_ma', 'vol_ratio', 'natr',
    # Candle patterns (15)
    'cdl_doji', 'cdl_hammer', 'cdl_engulf', 'cdl_morning', 'cdl_evening',
    'cdl_3white', 'cdl_3black', 'cdl_harami', 'cdl_piercing', 'cdl_darkcloud',
    'cdl_shooting', 'cdl_invhammer', 'cdl_marubozu', 'cdl_spinning', 'cdl_hangman',
    # Momentum (12)
    'rsi_7', 'rsi_14', 'rsi_slope', 'macd', 'macd_sig', 'macd_hist',
    'ema_cross', 'price_vs_ema5', 'price_vs_ema12', 'adx', 'plus_di', 'minus_di',
    # Oscillators (8)
    'stoch_k', 'stoch_d', 'cci', 'willr', 'mfi', 'obv_slope', 'cmo', 'roc'
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
