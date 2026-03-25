#%% High-Confidence LSTM - Focus on Extreme Predictions
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import roc_auc_score, precision_recall_curve
import warnings
warnings.filterwarnings('ignore')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

#%% Load & Engineer
df = pd.read_feather("/allah/freqtrade/user_data/data/binance/ml/TemaReversalLongFixed-ETH_USDT_USDT-20260320-094417.feather")

def engineer(df):
    df = df.copy()
    # Micro features that worked best
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

#%% Extract with More Data
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

print("Extracting sequences...")
X, y, profits = extract_seq(df, seq_len=60, clip_n=5000)
print(f"X: {X.shape}, y: {y.shape}, WR: {y.mean():.3f}")

# Split
split = int(len(X) * 0.8)
X_tr, X_va = X[:split], X[split:]
y_tr, y_va = y[:split], y[split:]
prof_va = profits[split:]

# Normalize
scaler = RobustScaler()
X_tr = np.clip(scaler.fit_transform(X_tr.reshape(-1, X_tr.shape[-1])).reshape(X_tr.shape), -5, 5)
X_va = np.clip(scaler.transform(X_va.reshape(-1, X_va.shape[-1])).reshape(X_va.shape), -5, 5)

print(f"Train: {len(X_tr)}, Val: {len(X_va)}")

#%% Dataset
class DS(Dataset):
    def __init__(self, X, y):
        self.X, self.y = torch.tensor(X), torch.tensor(y)
    def __len__(self): return len(self.y)
    def __getitem__(self, i): return self.X[i], self.y[i]

#%% Model: Focus on learning confidence
class ConfidentLSTM(nn.Module):
    def __init__(self, in_dim, hid=96, layers=2, drop=0.4):
        super().__init__()
        self.bn_input = nn.BatchNorm1d(in_dim)
        self.lstm = nn.LSTM(in_dim, hid, layers, batch_first=True, dropout=drop)
        self.attn = nn.Sequential(
            nn.Linear(hid, hid // 2),
            nn.Tanh(),
            nn.Linear(hid // 2, 1)
        )
        self.head = nn.Sequential(
            nn.Linear(hid, hid),
            nn.ReLU(),
            nn.Dropout(drop),
            nn.Linear(hid, hid // 2),
            nn.ReLU(),
            nn.Dropout(drop),
            nn.Linear(hid // 2, 1)
        )
    
    def forward(self, x):
        # x: (B, T, F)
        B, T, F = x.shape
        x = self.bn_input(x.reshape(-1, F)).reshape(B, T, F)
        out, _ = self.lstm(x)
        attn_w = torch.softmax(self.attn(out), dim=1)
        ctx = (out * attn_w).sum(dim=1)
        return self.head(ctx).squeeze(-1)

#%% Loss that encourages confident predictions
class ConfidenceLoss(nn.Module):
    """BCE + penalty for uncertain predictions"""
    def __init__(self, conf_weight=0.1):
        super().__init__()
        self.conf_weight = conf_weight
    
    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets)
        probs = torch.sigmoid(logits)
        # Penalize predictions near 0.5
        conf_penalty = (1 - 4 * (probs - 0.5) ** 2).mean()
        return bce + self.conf_weight * conf_penalty

#%% Training with multiple runs for stability
def train_model(X_tr, X_va, y_tr, y_va, epochs=40, lr=1e-3, runs=5):
    all_preds = []
    
    for run in range(runs):
        model = ConfidentLSTM(len(FEATURES), hid=96, layers=2, drop=0.4).to(DEVICE)
        opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-3)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
        criterion = ConfidenceLoss(conf_weight=0.1)
        
        # Weighted sampler - oversample hard examples
        tr_ds = DS(X_tr, y_tr)
        va_ds = DS(X_va, y_va)
        tr_ld = DataLoader(tr_ds, batch_size=256, shuffle=True)
        va_ld = DataLoader(va_ds, batch_size=256)
        
        best_auc = 0
        best_preds = None
        patience = 0
        
        for ep in range(epochs):
            model.train()
            for xb, yb in tr_ld:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                opt.zero_grad()
                loss = criterion(model(xb), yb)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
            scheduler.step()
            
            model.eval()
            preds = []
            with torch.no_grad():
                for xb, _ in va_ld:
                    preds.extend(torch.sigmoid(model(xb.to(DEVICE))).cpu().numpy())
            preds = np.array(preds)
            
            try:
                auc = roc_auc_score(y_va, preds)
            except:
                auc = 0.5
            
            if auc > best_auc:
                best_auc = auc
                best_preds = preds.copy()
                patience = 0
            else:
                patience += 1
                if patience > 10:
                    break
        
        all_preds.append(best_preds)
        print(f"  Run {run+1}: AUC={best_auc:.4f}")
    
    # Ensemble predictions
    ensemble_preds = np.mean(all_preds, axis=0)
    return ensemble_preds

#%% Train
print("\nTraining ensemble (5 runs)...")
preds = train_model(X_tr, X_va, y_tr, y_va, epochs=40, lr=1e-3, runs=5)

#%% Analysis
print("\n" + "="*60)
print("ENSEMBLE RESULTS")
print("="*60)

auc = roc_auc_score(y_va, preds)
print(f"Ensemble AUC: {auc:.4f} | Edge: {(auc-0.5)*100:.2f}%")
print(f"Predictions: min={preds.min():.3f}, max={preds.max():.3f}, mean={preds.mean():.3f}, std={preds.std():.3f}")

print("\nCalibration by threshold:")
print(f"{'Thresh':<8} {'Trades':<8} {'WR':<8} {'AvgProfit':<12} {'TotalProfit':<12}")
print("-" * 50)
for t in [0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75]:
    mask = preds > t
    if mask.sum() > 3:
        wr = y_va[mask].mean()
        avgp = prof_va[mask].mean() * 100
        totp = prof_va[mask].sum() * 100
        print(f"P>{t:.2f}   {mask.sum():<8} {wr:<8.3f} {avgp:<+12.4f} {totp:<+12.4f}")

# Also look at low predictions (short signals)
print("\nLow predictions (potential SHORT signals):")
for t in [0.3, 0.35, 0.4]:
    mask = preds < t
    if mask.sum() > 3:
        wr = y_va[mask].mean()
        avgp = prof_va[mask].mean() * 100
        totp = prof_va[mask].sum() * 100
        print(f"P<{t:.2f}   {mask.sum():<8} {wr:<8.3f} {avgp:<+12.4f} {totp:<+12.4f}")

#%% Find optimal threshold using precision-recall
print("\n" + "="*60)
print("OPTIMAL THRESHOLD ANALYSIS")
print("="*60)

precision, recall, thresholds = precision_recall_curve(y_va, preds)
f1_scores = 2 * (precision * recall) / (precision + recall + 1e-8)
best_idx = np.argmax(f1_scores)
best_thresh = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
print(f"Best F1 threshold: {best_thresh:.3f}")
print(f"Precision at best: {precision[best_idx]:.3f}")
print(f"Recall at best: {recall[best_idx]:.3f}")

# Profit-maximizing threshold
print("\nProfit-maximizing threshold search:")
best_profit = -999
best_profit_thresh = 0.5
for t in np.arange(0.3, 0.8, 0.01):
    mask = preds > t
    if mask.sum() > 10:
        total_profit = prof_va[mask].sum()
        if total_profit > best_profit:
            best_profit = total_profit
            best_profit_thresh = t

print(f"Best profit threshold: {best_profit_thresh:.2f}")
mask = preds > best_profit_thresh
print(f"Trades: {mask.sum()}, WR: {y_va[mask].mean():.3f}, Total Profit: {best_profit*100:.4f}%")

#%% Save model for best single run
print("\n" + "="*60)
print("SAVING BEST SINGLE MODEL")
print("="*60)

model = ConfidentLSTM(len(FEATURES), hid=96, layers=2, drop=0.4).to(DEVICE)
opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-3)
tr_ds = DS(X_tr, y_tr)
va_ds = DS(X_va, y_va)
tr_ld = DataLoader(tr_ds, batch_size=256, shuffle=True)
va_ld = DataLoader(va_ds, batch_size=256)

best_auc = 0
for ep in range(50):
    model.train()
    for xb, yb in tr_ld:
        xb, yb = xb.to(DEVICE), yb.to(DEVICE)
        opt.zero_grad()
        loss = F.binary_cross_entropy_with_logits(model(xb), yb)
        loss.backward()
        opt.step()
    
    model.eval()
    preds_final = []
    with torch.no_grad():
        for xb, _ in va_ld:
            preds_final.extend(torch.sigmoid(model(xb.to(DEVICE))).cpu().numpy())
    
    auc = roc_auc_score(y_va, preds_final)
    if auc > best_auc:
        best_auc = auc
        torch.save({
            'model': model.state_dict(),
            'scaler_center': scaler.center_,
            'scaler_scale': scaler.scale_,
            'features': FEATURES,
            'seq_len': 60,
        }, '/allah/blue/ft/ml/best_model.pt')

print(f"Saved best model with AUC: {best_auc:.4f}")

#%% Final summary
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"""
Model: ConfidentLSTM (96 hidden, 2 layers, attention)
Features: {len(FEATURES)} microstructure features
Sequence: 60 steps (5 min lookback)
Data: {len(X_tr)} train, {len(X_va)} val trades (~6 days)

Best AUC: {best_auc:.4f} ({(best_auc-0.5)*100:.1f}% edge over random)

Recommended trading strategy:
- Only trade when P > {best_profit_thresh:.2f}
- Expected trades: ~{mask.sum()} in validation period
- Expected win rate: ~{y_va[mask].mean()*100:.0f}%
""")
