#%% Final LSTM - Best practices combined
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import roc_auc_score
import json
import warnings
warnings.filterwarnings('ignore')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

#%% Load & Engineer (micro features that worked)
df = pd.read_feather("/allah/freqtrade/user_data/data/binance/ml/TemaReversalLongFixed-ETH_USDT_USDT-20260320-094417.feather")

def engineer(df):
    df = df.copy()
    for lag in [1, 3, 5, 12]:
        df[f'ret_{lag}'] = df['close'].pct_change(lag)
    df['log_ret'] = np.log(df['close'] / df['close'].shift(1))
    df['rvol_12'] = df['log_ret'].rolling(12).std()
    df['rvol_60'] = df['log_ret'].rolling(60).std()
    df['rvol_ratio'] = df['rvol_12'] / (df['rvol_60'] + 1e-8)
    df['hl_range'] = (df['high'] - df['low']) / (df['close'] + 1e-8)
    df['oc_range'] = (df['close'] - df['open']) / (df['close'] + 1e-8)
    df['body_pct'] = abs(df['close'] - df['open']) / (df['high'] - df['low'] + 1e-8)
    df['vol_ratio'] = df['volume'] / (df['volume'].rolling(12).mean() + 1e-8)
    df['vol_zscore'] = (df['volume'] - df['volume'].rolling(60).mean()) / (df['volume'].rolling(60).std() + 1e-8)
    df['signed_vol'] = df['volume'] * np.sign(df['close'] - df['open'])
    df['ofi_12'] = df['signed_vol'].rolling(12).sum()
    df['ofi_60'] = df['signed_vol'].rolling(60).sum()
    df['ofi_ratio'] = df['ofi_12'] / (np.abs(df['ofi_60']) + 1e-8)
    return df

df = engineer(df)
FEATURES = ['ret_1', 'ret_3', 'ret_5', 'ret_12', 'rvol_12', 'rvol_ratio', 'hl_range', 'oc_range', 'body_pct', 'vol_ratio', 'vol_zscore', 'ofi_ratio']

#%% Extract
def extract_seq(df, seq_len=60, clip_n=5000):
    trade_idx = df.index[df['label'].notna()].tolist()[:clip_n]
    X, y, profits = [], [], []
    for idx in trade_idx:
        pos = df.index.get_loc(idx)
        if pos < seq_len:
            continue
        seq = df.iloc[pos-seq_len:pos][FEATURES]
        if seq.isna().any().any():
            continue
        X.append(seq.values)
        y.append(df.loc[idx, 'is_winner'])
        profits.append(df.loc[idx, 'profit_ratio'])
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32), np.array(profits, dtype=np.float32)

X, y, profits = extract_seq(df, seq_len=60, clip_n=5000)
print(f"Data: {X.shape}, WR: {y.mean():.3f}")

split = int(len(X) * 0.8)
X_tr, X_va = X[:split], X[split:]
y_tr, y_va = y[:split], y[split:]
prof_va = profits[split:]

scaler = RobustScaler()
X_tr = np.clip(scaler.fit_transform(X_tr.reshape(-1, X_tr.shape[-1])).reshape(X_tr.shape), -5, 5)
X_va = np.clip(scaler.transform(X_va.reshape(-1, X_va.shape[-1])).reshape(X_va.shape), -5, 5)

#%% Dataset with augmentation
class DS(Dataset):
    def __init__(self, X, y, augment=False):
        self.X, self.y = torch.tensor(X), torch.tensor(y)
        self.augment = augment
    def __len__(self): return len(self.y)
    def __getitem__(self, i):
        x, y = self.X[i], self.y[i]
        if self.augment and torch.rand(1) < 0.3:
            x = x + torch.randn_like(x) * 0.05  # Add noise
        return x, y

#%% Simple but effective LSTM
class SimpleLSTM(nn.Module):
    def __init__(self, in_dim, hid=64, layers=2, drop=0.3):
        super().__init__()
        self.lstm = nn.LSTM(in_dim, hid, layers, batch_first=True, dropout=drop)
        self.head = nn.Linear(hid, 1)
    
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.head(out[:, -1, :]).squeeze(-1)

#%% Train multiple configs and pick best
configs = [
    {'hid': 64, 'layers': 2, 'drop': 0.3, 'lr': 1e-3, 'label_smooth': 0.0},
    {'hid': 64, 'layers': 2, 'drop': 0.3, 'lr': 1e-3, 'label_smooth': 0.1},
    {'hid': 64, 'layers': 2, 'drop': 0.3, 'lr': 5e-4, 'label_smooth': 0.0},
    {'hid': 64, 'layers': 2, 'drop': 0.5, 'lr': 1e-3, 'label_smooth': 0.0},
    {'hid': 96, 'layers': 2, 'drop': 0.3, 'lr': 1e-3, 'label_smooth': 0.0},
    {'hid': 128, 'layers': 2, 'drop': 0.3, 'lr': 5e-4, 'label_smooth': 0.0},
    {'hid': 64, 'layers': 3, 'drop': 0.3, 'lr': 5e-4, 'label_smooth': 0.0},
]

def train_config(cfg, epochs=30):
    model = SimpleLSTM(len(FEATURES), cfg['hid'], cfg['layers'], cfg['drop']).to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg['lr'], weight_decay=1e-4)
    
    tr_ld = DataLoader(DS(X_tr, y_tr, augment=True), batch_size=256, shuffle=True)
    va_ld = DataLoader(DS(X_va, y_va), batch_size=256)
    
    ls = cfg['label_smooth']
    best_auc = 0
    best_preds = None
    
    for ep in range(epochs):
        model.train()
        for xb, yb in tr_ld:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            if ls > 0:
                yb = yb * (1 - ls) + 0.5 * ls
            opt.zero_grad()
            loss = F.binary_cross_entropy_with_logits(model(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
        
        model.eval()
        preds = []
        with torch.no_grad():
            for xb, _ in va_ld:
                preds.extend(torch.sigmoid(model(xb.to(DEVICE))).cpu().numpy())
        preds = np.array(preds)
        
        auc = roc_auc_score(y_va, preds)
        if auc > best_auc:
            best_auc = auc
            best_preds = preds.copy()
            best_state = {k: v.cpu() for k, v in model.state_dict().items()}
    
    return best_auc, best_preds, best_state, cfg

print("\nTraining configs...")
results = []
for i, cfg in enumerate(configs):
    auc, preds, state, _ = train_config(cfg)
    results.append((auc, preds, state, cfg))
    print(f"  Config {i+1}: h={cfg['hid']}, l={cfg['layers']}, d={cfg['drop']}, lr={cfg['lr']}, ls={cfg['label_smooth']} -> AUC={auc:.4f}")

# Best config
best_auc, best_preds, best_state, best_cfg = max(results, key=lambda x: x[0])
print(f"\nBest config: {best_cfg} -> AUC={best_auc:.4f}")

#%% Analyze best predictions
print("\n" + "="*60)
print("BEST MODEL ANALYSIS")
print("="*60)

preds = best_preds
print(f"Predictions: min={preds.min():.3f}, max={preds.max():.3f}, mean={preds.mean():.3f}, std={preds.std():.3f}")

print("\nCalibration table:")
print(f"{'Threshold':<12} {'N Trades':<10} {'Win Rate':<10} {'Avg Profit':<12} {'Total Profit':<12}")
print("-" * 60)

best_total_profit = -999
best_thresh = 0.5
for t in np.arange(0.3, 0.85, 0.05):
    mask = preds > t
    if mask.sum() > 5:
        wr = y_va[mask].mean()
        avg_p = prof_va[mask].mean() * 100
        tot_p = prof_va[mask].sum() * 100
        print(f"P > {t:.2f}     {mask.sum():<10} {wr:<10.3f} {avg_p:<+12.4f} {tot_p:<+12.4f}")
        if tot_p > best_total_profit:
            best_total_profit = tot_p
            best_thresh = t

# Check low threshold (inverse)
print("\nLow confidence (inverse signal):")
for t in [0.3, 0.35, 0.4, 0.45]:
    mask = preds < t
    if mask.sum() > 5:
        wr = y_va[mask].mean()
        tot_p = prof_va[mask].sum() * 100
        print(f"P < {t:.2f}     {mask.sum():<10} {wr:<10.3f} {'':12} {tot_p:<+12.4f}")

#%% Optimal strategy
print("\n" + "="*60)
print("RECOMMENDED STRATEGY")
print("="*60)

mask = preds > best_thresh
n_trades = mask.sum()
wr = y_va[mask].mean()
total = prof_va[mask].sum() * 100

print(f"""
Threshold: P > {best_thresh:.2f}
Trades: {n_trades} (out of {len(y_va)} total)
Win Rate: {wr*100:.1f}%
Total Profit: {total:.4f}%
Profit per Trade: {total/n_trades:.4f}%

Edge over random: {(best_auc - 0.5) * 100:.2f}%
""")

#%% Save everything
torch.save({
    'model_state': best_state,
    'config': best_cfg,
    'features': FEATURES,
    'seq_len': 60,
    'scaler_center': scaler.center_,
    'scaler_scale': scaler.scale_,
    'best_auc': best_auc,
    'best_threshold': best_thresh,
}, '/allah/blue/ft/ml/final_model.pt')

print("Model saved to /allah/blue/ft/ml/final_model.pt")

#%% Quick sanity check - shuffle test
print("\n" + "="*60)
print("SANITY CHECK: Shuffle Test")
print("="*60)

np.random.seed(42)
y_shuffled = y_tr.copy()
np.random.shuffle(y_shuffled)

model = SimpleLSTM(len(FEATURES), best_cfg['hid'], best_cfg['layers'], best_cfg['drop']).to(DEVICE)
opt = torch.optim.AdamW(model.parameters(), lr=best_cfg['lr'])
tr_ld = DataLoader(DS(X_tr, y_shuffled), batch_size=256, shuffle=True)
va_ld = DataLoader(DS(X_va, y_va), batch_size=256)

for ep in range(30):
    model.train()
    for xb, yb in tr_ld:
        xb, yb = xb.to(DEVICE), yb.to(DEVICE)
        opt.zero_grad()
        F.binary_cross_entropy_with_logits(model(xb), yb).backward()
        opt.step()

model.eval()
preds_shuffle = []
with torch.no_grad():
    for xb, _ in va_ld:
        preds_shuffle.extend(torch.sigmoid(model(xb.to(DEVICE))).cpu().numpy())
shuffle_auc = roc_auc_score(y_va, preds_shuffle)

print(f"Real labels AUC: {best_auc:.4f}")
print(f"Shuffled labels AUC: {shuffle_auc:.4f}")
print(f"Difference: {(best_auc - shuffle_auc)*100:.2f}% (positive = model learned something real)")

if best_auc > shuffle_auc + 0.02:
    print("\n✓ Model has learned a real signal (not just noise)")
else:
    print("\n⚠ Model may be overfitting to noise")
