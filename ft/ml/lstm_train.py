#%% Imports
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import RobustScaler
from pathlib import Path

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

#%% Config
ML_DATA_DIR = "/allah/freqtrade/user_data/data/binance/ml/"
FEATHER_FILE = "TemaReversalLongFixed-ETH_USDT_USDT-20260320-094417.feather"

SEQ_LEN = 60  # 60 x 5s = 5 minutes lookback
CLIP_TRADES = 5000  # test on small subset first
BATCH_SIZE = 256
EPOCHS = 20
LR = 1e-3
HIDDEN_DIM = 64
NUM_LAYERS = 2
DROPOUT = 0.3

#%% Load Data
print(f"Loading {FEATHER_FILE}...")
df = pd.read_feather(ML_DATA_DIR + FEATHER_FILE)
print(f"Raw shape: {df.shape}")

#%% Jump Trading Style Feature Engineering
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Pro quant features inspired by Jump Trading / HFT style:
    - Microstructure: returns, volatility, volume imbalance
    - Price dynamics: momentum, mean reversion signals
    - Order flow proxies: volume-weighted price, trade intensity
    """
    df = df.copy()
    
    # === Returns & Log Returns ===
    df['ret_1'] = df['close'].pct_change(1)
    df['ret_5'] = df['close'].pct_change(5)
    df['ret_12'] = df['close'].pct_change(12)  # 1 min
    df['ret_60'] = df['close'].pct_change(60)  # 5 min
    df['log_ret'] = np.log(df['close'] / df['close'].shift(1))
    
    # === Realized Volatility (rolling) ===
    df['rvol_12'] = df['log_ret'].rolling(12).std() * np.sqrt(12)  # 1-min annualized proxy
    df['rvol_60'] = df['log_ret'].rolling(60).std() * np.sqrt(60)
    df['rvol_ratio'] = df['rvol_12'] / (df['rvol_60'] + 1e-8)  # vol regime
    
    # === Price Range / Microstructure ===
    df['hl_range'] = (df['high'] - df['low']) / (df['close'] + 1e-8)
    df['oc_range'] = (df['close'] - df['open']) / (df['close'] + 1e-8)
    df['upper_wick'] = (df['high'] - df[['open', 'close']].max(axis=1)) / (df['high'] - df['low'] + 1e-8)
    df['lower_wick'] = (df[['open', 'close']].min(axis=1) - df['low']) / (df['high'] - df['low'] + 1e-8)
    
    # === Volume Features ===
    df['vol_ma_12'] = df['volume'].rolling(12).mean()
    df['vol_ma_60'] = df['volume'].rolling(60).mean()
    df['vol_ratio'] = df['volume'] / (df['vol_ma_12'] + 1e-8)
    df['vol_zscore'] = (df['volume'] - df['vol_ma_60']) / (df['volume'].rolling(60).std() + 1e-8)
    
    # === VWAP Deviation ===
    df['vwap_12'] = (df['close'] * df['volume']).rolling(12).sum() / (df['volume'].rolling(12).sum() + 1e-8)
    df['vwap_dev'] = (df['close'] - df['vwap_12']) / (df['atr'] + 1e-8)
    
    # === Momentum / Mean Reversion ===
    df['close_vs_tema'] = (df['close'] - df['tema']) / (df['atr'] + 1e-8)
    df['tema_slope'] = (df['tema'] - df['tema'].shift(12)) / (df['atr'] + 1e-8)
    df['tema_accel'] = df['tema_slope'] - df['tema_slope'].shift(12)
    
    # === Order Flow Imbalance Proxy (using volume + direction) ===
    df['signed_vol'] = df['volume'] * np.sign(df['close'] - df['open'])
    df['ofi_12'] = df['signed_vol'].rolling(12).sum()
    df['ofi_60'] = df['signed_vol'].rolling(60).sum()
    df['ofi_ratio'] = df['ofi_12'] / (np.abs(df['ofi_60']) + 1e-8)
    
    # === Trade Intensity ===
    df['trades_ma'] = df['close_count'].rolling(12).mean() if 'close_count' in df.columns else 0
    df['trade_intensity'] = df['close_count'] / (df['trades_ma'] + 1e-8) if 'close_count' in df.columns else 0
    
    # === ATR Normalized Features ===
    df['atr_norm_ret'] = df['ret_1'] / (df['atr'] / df['close'] + 1e-8)
    
    # === Higher TF context (1m bars) ===
    if 'close_1m' in df.columns:
        df['ret_1m'] = df['close_1m'].pct_change(1)
        df['hl_range_1m'] = (df['high_1m'] - df['low_1m']) / (df['close_1m'] + 1e-8)
        df['vol_ratio_1m'] = df['volume_1m'] / (df['volume_1m'].rolling(60).mean() + 1e-8)
    
    return df

print("Engineering features...")
df = engineer_features(df)

#%% Select Feature Columns
FEATURE_COLS = [
    # Returns
    'ret_1', 'ret_5', 'ret_12', 'ret_60', 'log_ret',
    # Volatility
    'rvol_12', 'rvol_60', 'rvol_ratio',
    # Microstructure
    'hl_range', 'oc_range', 'upper_wick', 'lower_wick',
    # Volume
    'vol_ratio', 'vol_zscore',
    # VWAP
    'vwap_dev',
    # Momentum
    'close_vs_tema', 'tema_slope', 'tema_accel',
    # Order Flow
    'ofi_ratio',
    # ATR normalized
    'atr_norm_ret',
    # 1m context
    'ret_1m', 'hl_range_1m', 'vol_ratio_1m',
]

# Verify columns exist
FEATURE_COLS = [c for c in FEATURE_COLS if c in df.columns]
print(f"Using {len(FEATURE_COLS)} features: {FEATURE_COLS}")

#%% Extract Trade Sequences
def extract_trade_sequences(df: pd.DataFrame, seq_len: int, feature_cols: list, clip_n: int = None):
    """Extract sequences ending at each trade entry point."""
    
    # Find trade rows (where label exists)
    trade_mask = df['label'].notna()
    trade_indices = df.index[trade_mask].tolist()
    
    if clip_n:
        trade_indices = trade_indices[:clip_n]
    
    print(f"Extracting {len(trade_indices)} trade sequences...")
    
    sequences = []
    labels = []
    
    for idx in trade_indices:
        # Get position in dataframe
        pos = df.index.get_loc(idx)
        if pos < seq_len:
            continue
        
        # Extract sequence
        seq_df = df.iloc[pos - seq_len:pos][feature_cols]
        
        # Skip if any NaN
        if seq_df.isna().any().any():
            continue
        
        sequences.append(seq_df.values)
        labels.append(df.loc[idx, 'is_winner'])
    
    X = np.array(sequences, dtype=np.float32)
    y = np.array(labels, dtype=np.float32)
    
    return X, y

print(f"\nExtracting sequences (clip={CLIP_TRADES})...")
X, y = extract_trade_sequences(df, SEQ_LEN, FEATURE_COLS, clip_n=CLIP_TRADES)
print(f"X shape: {X.shape}")  # (n_trades, seq_len, n_features)
print(f"y shape: {y.shape}")
print(f"Win rate: {y.mean()*100:.1f}%")

#%% Train/Val Split (time-based, no shuffle)
split_idx = int(len(X) * 0.8)
X_train, X_val = X[:split_idx], X[split_idx:]
y_train, y_val = y[:split_idx], y[split_idx:]

print(f"\nTrain: {len(X_train)} samples ({y_train.mean()*100:.1f}% win)")
print(f"Val:   {len(X_val)} samples ({y_val.mean()*100:.1f}% win)")

#%% Normalize Features (fit on train only)
scaler = RobustScaler()
n_train, seq_len, n_feat = X_train.shape
X_train_flat = X_train.reshape(-1, n_feat)
scaler.fit(X_train_flat)

X_train = scaler.transform(X_train_flat).reshape(n_train, seq_len, n_feat)
X_val = scaler.transform(X_val.reshape(-1, n_feat)).reshape(len(X_val), seq_len, n_feat)

# Clip outliers
X_train = np.clip(X_train, -5, 5)
X_val = np.clip(X_val, -5, 5)

print(f"\nNormalized - Train range: [{X_train.min():.2f}, {X_train.max():.2f}]")

#%% PyTorch Dataset
class TradeDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

train_ds = TradeDataset(X_train, y_train)
val_ds = TradeDataset(X_val, y_val)

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)

#%% LSTM Model
class TradeLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers, dropout):
        super().__init__()
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=False
        )
        
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1),
        )
        
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )
    
    def forward(self, x):
        # x: (batch, seq_len, features)
        lstm_out, _ = self.lstm(x)  # (batch, seq_len, hidden)
        
        # Attention over time steps
        attn_weights = torch.softmax(self.attention(lstm_out), dim=1)  # (batch, seq_len, 1)
        context = (lstm_out * attn_weights).sum(dim=1)  # (batch, hidden)
        
        logits = self.classifier(context).squeeze(-1)  # (batch,)
        return logits

model = TradeLSTM(
    input_dim=len(FEATURE_COLS),
    hidden_dim=HIDDEN_DIM,
    num_layers=NUM_LAYERS,
    dropout=DROPOUT
).to(DEVICE)

print(f"\nModel params: {sum(p.numel() for p in model.parameters()):,}")

#%% Training
criterion = nn.BCEWithLogitsLoss()
optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)

def evaluate(model, loader):
    model.eval()
    preds, targets = [], []
    total_loss = 0
    with torch.no_grad():
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(DEVICE), y_batch.to(DEVICE)
            logits = model(X_batch)
            loss = criterion(logits, y_batch)
            total_loss += loss.item() * len(y_batch)
            preds.extend(torch.sigmoid(logits).cpu().numpy())
            targets.extend(y_batch.cpu().numpy())
    
    preds = np.array(preds)
    targets = np.array(targets)
    pred_binary = (preds > 0.5).astype(int)
    
    acc = (pred_binary == targets).mean()
    # AUC
    from sklearn.metrics import roc_auc_score
    try:
        auc = roc_auc_score(targets, preds)
    except:
        auc = 0.5
    
    return total_loss / len(loader.dataset), acc, auc

print("\n" + "="*60)
print("TRAINING")
print("="*60)

best_auc = 0
for epoch in range(EPOCHS):
    model.train()
    train_loss = 0
    for X_batch, y_batch in train_loader:
        X_batch, y_batch = X_batch.to(DEVICE), y_batch.to(DEVICE)
        
        optimizer.zero_grad()
        logits = model(X_batch)
        loss = criterion(logits, y_batch)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        
        train_loss += loss.item() * len(y_batch)
    
    train_loss /= len(train_loader.dataset)
    val_loss, val_acc, val_auc = evaluate(model, val_loader)
    scheduler.step(val_loss)
    
    if val_auc > best_auc:
        best_auc = val_auc
        torch.save(model.state_dict(), "/allah/blue/ft/ml/best_lstm.pt")
    
    print(f"Epoch {epoch+1:2d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.3f} | Val AUC: {val_auc:.3f}")

#%% Final Evaluation
print("\n" + "="*60)
print("FINAL EVALUATION")
print("="*60)

model.load_state_dict(torch.load("/allah/blue/ft/ml/best_lstm.pt"))
val_loss, val_acc, val_auc = evaluate(model, val_loader)

print(f"Best Val AUC: {val_auc:.4f}")
print(f"Val Accuracy: {val_acc:.4f}")
print(f"Baseline (random): 0.5000")
print(f"Edge over random: {(val_auc - 0.5)*100:.2f}%")

# Detailed predictions
model.eval()
with torch.no_grad():
    all_preds = []
    for X_batch, _ in val_loader:
        X_batch = X_batch.to(DEVICE)
        logits = model(X_batch)
        all_preds.extend(torch.sigmoid(logits).cpu().numpy())

all_preds = np.array(all_preds)
print(f"\nPrediction distribution:")
print(f"  Min: {all_preds.min():.3f}")
print(f"  Max: {all_preds.max():.3f}")
print(f"  Mean: {all_preds.mean():.3f}")
print(f"  Std: {all_preds.std():.3f}")

# Calibration buckets
print(f"\nCalibration (predicted vs actual win rate):")
for thresh in [0.3, 0.4, 0.5, 0.6, 0.7]:
    mask = all_preds > thresh
    if mask.sum() > 0:
        actual_wr = y_val[mask].mean()
        print(f"  P>{thresh}: {mask.sum():4d} trades, actual WR: {actual_wr:.3f}")
