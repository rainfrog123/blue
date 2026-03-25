#%% Imports
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import roc_auc_score
import warnings
warnings.filterwarnings('ignore')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

#%% Load Data
df = pd.read_feather("/allah/freqtrade/user_data/data/binance/ml/TemaReversalLongFixed-ETH_USDT_USDT-20260320-094417.feather")
print(f"Loaded: {df.shape}")

#%% Feature Engineering
def engineer(df):
    df = df.copy()
    
    # Returns
    for lag in [1, 3, 5, 12, 30, 60]:
        df[f'ret_{lag}'] = df['close'].pct_change(lag)
    df['log_ret'] = np.log(df['close'] / df['close'].shift(1))
    
    # Volatility
    df['rvol_12'] = df['log_ret'].rolling(12).std()
    df['rvol_60'] = df['log_ret'].rolling(60).std()
    df['rvol_ratio'] = df['rvol_12'] / (df['rvol_60'] + 1e-8)
    
    # Candles
    df['hl_range'] = (df['high'] - df['low']) / (df['close'] + 1e-8)
    df['oc_range'] = (df['close'] - df['open']) / (df['close'] + 1e-8)
    df['body_pct'] = abs(df['close'] - df['open']) / (df['high'] - df['low'] + 1e-8)
    
    # Volume
    df['vol_ratio'] = df['volume'] / (df['volume'].rolling(12).mean() + 1e-8)
    df['vol_zscore'] = (df['volume'] - df['volume'].rolling(60).mean()) / (df['volume'].rolling(60).std() + 1e-8)
    
    # VWAP
    df['vwap'] = (df['close'] * df['volume']).rolling(12).sum() / (df['volume'].rolling(12).sum() + 1e-8)
    df['vwap_dev'] = (df['close'] - df['vwap']) / (df['atr'] + 1e-8)
    
    # TEMA
    df['close_vs_tema'] = (df['close'] - df['tema']) / (df['atr'] + 1e-8)
    df['tema_slope'] = (df['tema'] - df['tema'].shift(12)) / (df['atr'] + 1e-8)
    
    # Order flow
    df['signed_vol'] = df['volume'] * np.sign(df['close'] - df['open'])
    df['ofi_12'] = df['signed_vol'].rolling(12).sum()
    df['ofi_60'] = df['signed_vol'].rolling(60).sum()
    df['ofi_ratio'] = df['ofi_12'] / (np.abs(df['ofi_60']) + 1e-8)
    
    # Position in range
    df['close_pos'] = (df['close'] - df['low'].rolling(60).min()) / (df['high'].rolling(60).max() - df['low'].rolling(60).min() + 1e-8)
    
    # 1m TF
    if 'close_1m' in df.columns:
        df['ret_1m'] = df['close_1m'].pct_change()
        df['hl_1m'] = (df['high_1m'] - df['low_1m']) / (df['close_1m'] + 1e-8)
    
    return df

df = engineer(df)

#%% Feature Sets
FEAT_SETS = {
    'minimal': ['ret_1', 'ret_5', 'ret_12', 'rvol_12', 'vol_ratio', 'close_vs_tema'],
    'micro': ['ret_1', 'ret_3', 'ret_5', 'ret_12', 'rvol_12', 'rvol_ratio', 'hl_range', 'oc_range', 'body_pct', 'vol_ratio', 'vol_zscore', 'ofi_ratio'],
    'full': ['ret_1', 'ret_3', 'ret_5', 'ret_12', 'ret_30', 'ret_60', 'log_ret', 'rvol_12', 'rvol_60', 'rvol_ratio', 'hl_range', 'oc_range', 'body_pct', 'vol_ratio', 'vol_zscore', 'vwap_dev', 'close_vs_tema', 'tema_slope', 'ofi_ratio', 'close_pos'],
}

#%% Extract Sequences
def extract_seq(df, seq_len, feat_cols, clip_n=5000):
    valid_cols = [c for c in feat_cols if c in df.columns]
    trade_idx = df.index[df['label'].notna()].tolist()[:clip_n]
    
    X, y, profits = [], [], []
    for idx in trade_idx:
        pos = df.index.get_loc(idx)
        if pos < seq_len:
            continue
        seq = df.iloc[pos-seq_len:pos][valid_cols]
        if seq.isna().any().any():
            continue
        X.append(seq.values)
        y.append(df.loc[idx, 'is_winner'])
        profits.append(df.loc[idx, 'profit_ratio'])
    
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32), np.array(profits, dtype=np.float32), valid_cols

#%% Models
class LSTM(nn.Module):
    def __init__(self, in_dim, hid=64, layers=2, drop=0.3, bidir=False, attn=False):
        super().__init__()
        self.attn = attn
        self.lstm = nn.LSTM(in_dim, hid, layers, batch_first=True, dropout=drop if layers > 1 else 0, bidirectional=bidir)
        out_dim = hid * 2 if bidir else hid
        if attn:
            self.att_layer = nn.Linear(out_dim, 1)
        self.fc = nn.Sequential(nn.Linear(out_dim, hid//2), nn.ReLU(), nn.Dropout(drop), nn.Linear(hid//2, 1))
    
    def forward(self, x):
        out, _ = self.lstm(x)
        if self.attn:
            w = torch.softmax(self.att_layer(out), dim=1)
            out = (out * w).sum(dim=1)
        else:
            out = out[:, -1, :]
        return self.fc(out).squeeze(-1)

class TCN(nn.Module):
    def __init__(self, in_dim, hid=64, layers=3, drop=0.3, **kw):
        super().__init__()
        convs = []
        for i in range(layers):
            convs += [nn.Conv1d(in_dim if i == 0 else hid, hid, 3, padding=2**i, dilation=2**i), nn.ReLU(), nn.Dropout(drop)]
        self.conv = nn.Sequential(*convs)
        self.fc = nn.Linear(hid, 1)
    
    def forward(self, x):
        x = x.permute(0, 2, 1)
        return self.fc(self.conv(x)[:, :, -1]).squeeze(-1)

#%% Dataset & Training
class DS(Dataset):
    def __init__(self, X, y):
        self.X, self.y = torch.tensor(X), torch.tensor(y)
    def __len__(self): return len(self.y)
    def __getitem__(self, i): return self.X[i], self.y[i]

def train(model, tr_ld, va_ld, epochs=25, lr=1e-3):
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    crit = nn.BCEWithLogitsLoss()
    best_auc = 0
    
    for ep in range(epochs):
        model.train()
        for xb, yb in tr_ld:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            opt.zero_grad()
            loss = crit(model(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        
        model.eval()
        preds, targs = [], []
        with torch.no_grad():
            for xb, yb in va_ld:
                preds.extend(torch.sigmoid(model(xb.to(DEVICE))).cpu().numpy())
                targs.extend(yb.numpy())
        try:
            auc = roc_auc_score(targs, preds)
        except:
            auc = 0.5
        best_auc = max(best_auc, auc)
    
    return best_auc, np.array(preds), np.array(targs)

#%% Run Experiments
results = []
configs = [
    # (name, model_fn, feat_set, seq_len, hidden, lr)
    ('LSTM-minimal-20', lambda d: LSTM(d, 64, 2), 'minimal', 20, 64, 1e-3),
    ('LSTM-minimal-60', lambda d: LSTM(d, 64, 2), 'minimal', 60, 64, 1e-3),
    ('LSTM-micro-20', lambda d: LSTM(d, 64, 2), 'micro', 20, 64, 1e-3),
    ('LSTM-micro-60', lambda d: LSTM(d, 64, 2), 'micro', 60, 64, 1e-3),
    ('LSTM-full-20', lambda d: LSTM(d, 64, 2), 'full', 20, 64, 1e-3),
    ('LSTM-full-60', lambda d: LSTM(d, 64, 2), 'full', 60, 64, 1e-3),
    ('AttnLSTM-micro-40', lambda d: LSTM(d, 64, 2, attn=True), 'micro', 40, 64, 1e-3),
    ('AttnLSTM-full-40', lambda d: LSTM(d, 64, 2, attn=True), 'full', 40, 64, 1e-3),
    ('AttnLSTM-full-60', lambda d: LSTM(d, 128, 2, attn=True), 'full', 60, 128, 5e-4),
    ('BiLSTM-micro-40', lambda d: LSTM(d, 64, 2, bidir=True), 'micro', 40, 64, 1e-3),
    ('BiLSTM-full-40', lambda d: LSTM(d, 64, 2, bidir=True), 'full', 40, 64, 1e-3),
    ('BiLSTM-full-60', lambda d: LSTM(d, 64, 2, bidir=True), 'full', 60, 64, 5e-4),
    ('TCN-micro-40', lambda d: TCN(d, 64, 3), 'micro', 40, 64, 1e-3),
    ('TCN-full-40', lambda d: TCN(d, 64, 3), 'full', 40, 64, 1e-3),
    ('TCN-full-60', lambda d: TCN(d, 64, 4), 'full', 60, 64, 1e-3),
    ('DeepLSTM-full-60', lambda d: LSTM(d, 128, 3), 'full', 60, 128, 5e-4),
    ('DeepAttn-full-100', lambda d: LSTM(d, 128, 3, attn=True), 'full', 100, 128, 5e-4),
    ('WideLSTM-full-40', lambda d: LSTM(d, 256, 2), 'full', 40, 256, 5e-4),
]

print("\n" + "="*70)
print(f"{'Name':<25} {'AUC':>7} {'Acc':>7} {'Edge':>7} {'n_feat':>6} {'seq':>4}")
print("="*70)

for name, model_fn, feat_name, seq_len, hid, lr in configs:
    X, y, profits, valid_cols = extract_seq(df, seq_len, FEAT_SETS[feat_name], 5000)
    
    split = int(len(X) * 0.8)
    X_tr, X_va = X[:split], X[split:]
    y_tr, y_va = y[:split], y[split:]
    prof_va = profits[split:]
    
    # Normalize
    scaler = RobustScaler()
    X_tr = np.clip(scaler.fit_transform(X_tr.reshape(-1, X_tr.shape[-1])).reshape(X_tr.shape), -5, 5)
    X_va = np.clip(scaler.transform(X_va.reshape(-1, X_va.shape[-1])).reshape(X_va.shape), -5, 5)
    
    tr_ld = DataLoader(DS(X_tr, y_tr), batch_size=256, shuffle=True)
    va_ld = DataLoader(DS(X_va, y_va), batch_size=256)
    
    model = model_fn(len(valid_cols)).to(DEVICE)
    auc, preds, targs = train(model, tr_ld, va_ld, epochs=25, lr=lr)
    acc = (np.array(preds) > 0.5).astype(int)
    acc = (acc == targs).mean()
    edge = (auc - 0.5) * 100
    
    results.append({'name': name, 'auc': auc, 'acc': acc, 'edge': edge, 'preds': preds, 'targs': targs, 'profits': prof_va, 'y_va': y_va})
    print(f"{name:<25} {auc:>7.4f} {acc:>7.4f} {edge:>+6.2f}% {len(valid_cols):>6} {seq_len:>4}")

#%% Best Result Analysis
print("\n" + "="*70)
print("BEST MODEL ANALYSIS")
print("="*70)

best = max(results, key=lambda x: x['auc'])
print(f"\nBest: {best['name']} | AUC: {best['auc']:.4f} | Edge: {best['edge']:.2f}%")

preds, y_va, profits = best['preds'], best['y_va'], best['profits']
print(f"\nPrediction stats: min={preds.min():.3f}, max={preds.max():.3f}, mean={preds.mean():.3f}, std={preds.std():.3f}")

print(f"\nCalibration (threshold -> trades, win rate, avg profit):")
for t in [0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65]:
    mask = preds > t
    if mask.sum() > 5:
        wr = y_va[mask].mean()
        avgp = profits[mask].mean() * 100
        print(f"  P>{t:.2f}: {mask.sum():4d} trades | WR={wr:.3f} | AvgProfit={avgp:+.4f}%")

# Filter: only trade high confidence
print(f"\nFiltered trading (only high conf):")
for t in [0.55, 0.6, 0.65]:
    mask = preds > t
    if mask.sum() > 5:
        total_profit = profits[mask].sum() * 100
        n_trades = mask.sum()
        print(f"  P>{t:.2f}: {n_trades:4d} trades | Total Profit={total_profit:+.4f}% | Avg={total_profit/n_trades:+.4f}%")

#%% Alternative Target: Predict Profit Ratio
print("\n" + "="*70)
print("REGRESSION: Predict Profit Ratio")
print("="*70)

X, y_class, profits, valid_cols = extract_seq(df, 60, FEAT_SETS['full'], 5000)
split = int(len(X) * 0.8)
X_tr, X_va = X[:split], X[split:]
prof_tr, prof_va = profits[:split], profits[split:]
y_va_class = y_class[split:]

scaler = RobustScaler()
X_tr = np.clip(scaler.fit_transform(X_tr.reshape(-1, X_tr.shape[-1])).reshape(X_tr.shape), -5, 5)
X_va = np.clip(scaler.transform(X_va.reshape(-1, X_va.shape[-1])).reshape(X_va.shape), -5, 5)

class DSReg(Dataset):
    def __init__(self, X, y):
        self.X, self.y = torch.tensor(X), torch.tensor(y * 100)  # Scale profits
    def __len__(self): return len(self.y)
    def __getitem__(self, i): return self.X[i], self.y[i]

model = LSTM(len(valid_cols), 128, 2, attn=True).to(DEVICE)
opt = torch.optim.AdamW(model.parameters(), lr=5e-4)
tr_ld = DataLoader(DSReg(X_tr, prof_tr), batch_size=256, shuffle=True)
va_ld = DataLoader(DSReg(X_va, prof_va), batch_size=256)

for ep in range(30):
    model.train()
    for xb, yb in tr_ld:
        xb, yb = xb.to(DEVICE), yb.to(DEVICE)
        opt.zero_grad()
        loss = F.mse_loss(model(xb), yb)
        loss.backward()
        opt.step()

model.eval()
preds_reg = []
with torch.no_grad():
    for xb, _ in va_ld:
        preds_reg.extend(model(xb.to(DEVICE)).cpu().numpy())
preds_reg = np.array(preds_reg)

corr = np.corrcoef(preds_reg, prof_va * 100)[0, 1]
print(f"Correlation(pred, actual profit): {corr:.4f}")

# Use regression to filter trades
print(f"\nUsing regression predictions to filter:")
for t in [0.0, 0.05, 0.1]:
    mask = preds_reg > t
    if mask.sum() > 5:
        wr = y_va_class[mask].mean()
        total = profits[split:][mask].sum() * 100
        n = mask.sum()
        print(f"  PredProfit>{t:.2f}%: {n:4d} trades | WR={wr:.3f} | TotalProfit={total:+.4f}%")

print("\n" + "="*70)
print("DONE")
print("="*70)
