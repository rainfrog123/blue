#%% Imports
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.metrics import roc_auc_score, accuracy_score
import warnings
warnings.filterwarnings('ignore')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

#%% Load Data
ML_DATA_DIR = "/allah/freqtrade/user_data/data/binance/ml/"
FEATHER_FILE = "TemaReversalLongFixed-ETH_USDT_USDT-20260320-094417.feather"

print(f"Loading {FEATHER_FILE}...")
df_raw = pd.read_feather(ML_DATA_DIR + FEATHER_FILE)
print(f"Raw shape: {df_raw.shape}")

#%% Feature Engineering - Multiple Feature Sets
def add_all_features(df):
    df = df.copy()
    
    # === Basic Returns ===
    for lag in [1, 2, 3, 5, 10, 12, 20, 30, 60]:
        df[f'ret_{lag}'] = df['close'].pct_change(lag)
    
    df['log_ret'] = np.log(df['close'] / df['close'].shift(1))
    
    # === Volatility ===
    for win in [5, 12, 30, 60]:
        df[f'rvol_{win}'] = df['log_ret'].rolling(win).std()
    
    df['rvol_ratio'] = df['rvol_12'] / (df['rvol_60'] + 1e-8)
    
    # === Price Position ===
    for win in [12, 30, 60]:
        df[f'close_vs_high_{win}'] = (df['close'] - df['high'].rolling(win).max()) / (df['atr'] + 1e-8)
        df[f'close_vs_low_{win}'] = (df['close'] - df['low'].rolling(win).min()) / (df['atr'] + 1e-8)
        df[f'close_vs_mean_{win}'] = (df['close'] - df['close'].rolling(win).mean()) / (df['atr'] + 1e-8)
    
    # === Candle Features ===
    df['hl_range'] = (df['high'] - df['low']) / (df['close'] + 1e-8)
    df['oc_range'] = (df['close'] - df['open']) / (df['close'] + 1e-8)
    df['body_pct'] = abs(df['close'] - df['open']) / (df['high'] - df['low'] + 1e-8)
    df['upper_wick'] = (df['high'] - df[['open', 'close']].max(axis=1)) / (df['high'] - df['low'] + 1e-8)
    df['lower_wick'] = (df[['open', 'close']].min(axis=1) - df['low']) / (df['high'] - df['low'] + 1e-8)
    
    # === Volume ===
    for win in [5, 12, 30, 60]:
        df[f'vol_ma_{win}'] = df['volume'].rolling(win).mean()
    df['vol_ratio'] = df['volume'] / (df['vol_ma_12'] + 1e-8)
    df['vol_zscore'] = (df['volume'] - df['vol_ma_60']) / (df['volume'].rolling(60).std() + 1e-8)
    
    # === VWAP ===
    df['vwap_12'] = (df['close'] * df['volume']).rolling(12).sum() / (df['volume'].rolling(12).sum() + 1e-8)
    df['vwap_60'] = (df['close'] * df['volume']).rolling(60).sum() / (df['volume'].rolling(60).sum() + 1e-8)
    df['vwap_dev_12'] = (df['close'] - df['vwap_12']) / (df['atr'] + 1e-8)
    df['vwap_dev_60'] = (df['close'] - df['vwap_60']) / (df['atr'] + 1e-8)
    
    # === TEMA Features ===
    df['close_vs_tema'] = (df['close'] - df['tema']) / (df['atr'] + 1e-8)
    df['tema_slope'] = (df['tema'] - df['tema'].shift(12)) / (df['atr'] + 1e-8)
    df['tema_accel'] = df['tema_slope'] - df['tema_slope'].shift(12)
    
    # === Order Flow Proxy ===
    df['signed_vol'] = df['volume'] * np.sign(df['close'] - df['open'])
    for win in [5, 12, 30, 60]:
        df[f'ofi_{win}'] = df['signed_vol'].rolling(win).sum()
    df['ofi_ratio'] = df['ofi_12'] / (np.abs(df['ofi_60']) + 1e-8)
    
    # === Momentum ===
    df['rsi_proxy'] = df['ret_1'].rolling(14).apply(lambda x: (x > 0).sum() / len(x), raw=True)
    
    # === 1m TF features ===
    if 'close_1m' in df.columns:
        df['ret_1m'] = df['close_1m'].pct_change()
        df['hl_range_1m'] = (df['high_1m'] - df['low_1m']) / (df['close_1m'] + 1e-8)
        df['vol_ratio_1m'] = df['volume_1m'] / (df['volume_1m'].rolling(60).mean() + 1e-8)
    
    # === Trend strength ===
    if 'trend' in df.columns:
        df['trend_num'] = df['trend'].map({'UP': 1, 'DOWN': -1}).fillna(0)
        df['trend_strength'] = df['trend_num'].rolling(12).mean()
    else:
        df['trend_strength'] = 0
    
    # === Time features (cyclical) ===
    if 'date' in df.columns:
        df['hour'] = pd.to_datetime(df['date']).dt.hour
        df['minute'] = pd.to_datetime(df['date']).dt.minute
        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
    
    return df

print("Engineering all features...")
df = add_all_features(df_raw)

#%% Define Feature Sets
FEATURE_SETS = {
    'minimal': ['ret_1', 'ret_5', 'ret_12', 'rvol_12', 'vol_ratio', 'close_vs_tema'],
    
    'returns_only': ['ret_1', 'ret_2', 'ret_3', 'ret_5', 'ret_10', 'ret_12', 'ret_20', 'ret_30', 'ret_60', 'log_ret'],
    
    'microstructure': [
        'ret_1', 'ret_5', 'ret_12', 'rvol_12', 'rvol_ratio',
        'hl_range', 'oc_range', 'body_pct', 'upper_wick', 'lower_wick',
        'vol_ratio', 'vol_zscore', 'ofi_ratio'
    ],
    
    'full': [
        'ret_1', 'ret_5', 'ret_12', 'ret_60', 'log_ret',
        'rvol_12', 'rvol_60', 'rvol_ratio',
        'close_vs_high_12', 'close_vs_low_12', 'close_vs_mean_12',
        'hl_range', 'oc_range', 'body_pct', 'upper_wick', 'lower_wick',
        'vol_ratio', 'vol_zscore',
        'vwap_dev_12', 'vwap_dev_60',
        'close_vs_tema', 'tema_slope', 'tema_accel',
        'ofi_ratio', 'rsi_proxy',
    ],
    
    'raw_ohlcv': ['open', 'high', 'low', 'close', 'volume'],
}

#%% Extract Sequences
def extract_sequences(df, seq_len, feature_cols, clip_n=5000):
    trade_mask = df['label'].notna()
    trade_indices = df.index[trade_mask].tolist()[:clip_n]
    
    # Filter valid features
    valid_cols = [c for c in feature_cols if c in df.columns]
    
    sequences, labels, profit_ratios = [], [], []
    
    for idx in trade_indices:
        pos = df.index.get_loc(idx)
        if pos < seq_len:
            continue
        
        seq_df = df.iloc[pos - seq_len:pos][valid_cols]
        if seq_df.isna().any().any():
            continue
        
        sequences.append(seq_df.values)
        labels.append(df.loc[idx, 'is_winner'])
        profit_ratios.append(df.loc[idx, 'profit_ratio'])
    
    return (np.array(sequences, dtype=np.float32), 
            np.array(labels, dtype=np.float32),
            np.array(profit_ratios, dtype=np.float32),
            valid_cols)

#%% Models
class SimpleLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=dropout if num_layers > 1 else 0)
        self.fc = nn.Linear(hidden_dim, 1)
    
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :]).squeeze(-1)

class AttentionLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=dropout if num_layers > 1 else 0)
        self.attn = nn.Linear(hidden_dim, 1)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1)
        )
    
    def forward(self, x):
        out, _ = self.lstm(x)
        attn_w = torch.softmax(self.attn(out), dim=1)
        context = (out * attn_w).sum(dim=1)
        return self.fc(context).squeeze(-1)

class BiLSTM(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=dropout if num_layers > 1 else 0, bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, 1)
    
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :]).squeeze(-1)

class TCN(nn.Module):
    """Temporal Convolutional Network"""
    def __init__(self, input_dim, hidden_dim=64, num_layers=3, dropout=0.3):
        super().__init__()
        layers = []
        for i in range(num_layers):
            in_ch = input_dim if i == 0 else hidden_dim
            layers.append(nn.Conv1d(in_ch, hidden_dim, kernel_size=3, padding=2**i, dilation=2**i))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout))
        self.conv = nn.Sequential(*layers)
        self.fc = nn.Linear(hidden_dim, 1)
    
    def forward(self, x):
        x = x.permute(0, 2, 1)  # (B, C, T)
        out = self.conv(x)
        return self.fc(out[:, :, -1]).squeeze(-1)

class TransformerModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, dropout=0.3):
        super().__init__()
        self.embed = nn.Linear(input_dim, hidden_dim)
        encoder_layer = nn.TransformerEncoderLayer(d_model=hidden_dim, nhead=4, dropout=dropout, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(hidden_dim, 1)
    
    def forward(self, x):
        x = self.embed(x)
        out = self.transformer(x)
        return self.fc(out[:, -1, :]).squeeze(-1)

#%% Loss Functions
class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, alpha=0.5):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha
    
    def forward(self, logits, targets):
        bce = F.binary_cross_entropy_with_logits(logits, targets, reduction='none')
        pt = torch.exp(-bce)
        focal = self.alpha * (1 - pt) ** self.gamma * bce
        return focal.mean()

#%% Training Function
def train_model(model, train_loader, val_loader, epochs=30, lr=1e-3, loss_fn='bce', patience=5):
    if loss_fn == 'bce':
        criterion = nn.BCEWithLogitsLoss()
    elif loss_fn == 'focal':
        criterion = FocalLoss()
    elif loss_fn == 'weighted_bce':
        # Weight positives more
        pos_weight = torch.tensor([1.2]).to(DEVICE)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    else:
        criterion = nn.BCEWithLogitsLoss()
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
    
    best_auc = 0
    no_improve = 0
    
    for epoch in range(epochs):
        model.train()
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(DEVICE), y_batch.to(DEVICE)
            optimizer.zero_grad()
            logits = model(X_batch)
            loss = criterion(logits, y_batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        
        # Validate
        model.eval()
        preds, targets = [], []
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch = X_batch.to(DEVICE)
                logits = model(X_batch)
                preds.extend(torch.sigmoid(logits).cpu().numpy())
                targets.extend(y_batch.numpy())
        
        preds = np.array(preds)
        targets = np.array(targets)
        try:
            auc = roc_auc_score(targets, preds)
        except:
            auc = 0.5
        
        scheduler.step(1 - auc)
        
        if auc > best_auc:
            best_auc = auc
            no_improve = 0
        else:
            no_improve += 1
            if no_improve >= patience:
                break
    
    return best_auc, preds, targets

#%% Dataset
class TradeDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

#%% Run Experiments
def run_experiment(name, X_train, X_val, y_train, y_val, model_class, hidden_dim=64, num_layers=2, 
                   dropout=0.3, lr=1e-3, loss_fn='bce', epochs=30, batch_size=256):
    
    train_ds = TradeDataset(X_train, y_train)
    val_ds = TradeDataset(X_val, y_val)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    
    input_dim = X_train.shape[2]
    model = model_class(input_dim, hidden_dim, num_layers, dropout).to(DEVICE)
    
    auc, preds, targets = train_model(model, train_loader, val_loader, epochs, lr, loss_fn)
    acc = accuracy_score(targets, (np.array(preds) > 0.5).astype(int))
    
    return auc, acc, preds

#%% Main Experiment Loop
CLIP_TRADES = 5000
SEQ_LENS = [20, 40, 60, 100]
BATCH_SIZE = 256

results = []

print("\n" + "="*80)
print("RUNNING EXPERIMENTS")
print("="*80)

for seq_len in SEQ_LENS:
    for feat_name, feat_cols in FEATURE_SETS.items():
        X, y, profits, valid_cols = extract_sequences(df, seq_len, feat_cols, CLIP_TRADES)
        
        if len(X) < 100:
            continue
        
        # Split
        split_idx = int(len(X) * 0.8)
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]
        
        # Normalize
        scaler = RobustScaler()
        n_train, sl, nf = X_train.shape
        X_train = scaler.fit_transform(X_train.reshape(-1, nf)).reshape(n_train, sl, nf)
        X_val = scaler.transform(X_val.reshape(-1, nf)).reshape(len(X_val), sl, nf)
        X_train = np.clip(X_train, -5, 5)
        X_val = np.clip(X_val, -5, 5)
        
        # Test different models
        models_to_test = [
            ('SimpleLSTM', SimpleLSTM),
            ('AttentionLSTM', AttentionLSTM),
            ('BiLSTM', BiLSTM),
            ('TCN', TCN),
            ('Transformer', TransformerModel),
        ]
        
        for model_name, model_class in models_to_test:
            for loss_fn in ['bce', 'focal']:
                for hidden in [32, 64, 128]:
                    for lr in [1e-3, 5e-4]:
                        try:
                            auc, acc, preds = run_experiment(
                                f"{model_name}_{feat_name}_seq{seq_len}",
                                X_train, X_val, y_train, y_val,
                                model_class, hidden_dim=hidden, lr=lr, loss_fn=loss_fn
                            )
                            
                            result = {
                                'seq_len': seq_len,
                                'features': feat_name,
                                'n_features': len(valid_cols),
                                'model': model_name,
                                'hidden': hidden,
                                'lr': lr,
                                'loss': loss_fn,
                                'auc': auc,
                                'acc': acc,
                                'edge': (auc - 0.5) * 100
                            }
                            results.append(result)
                            
                            if auc > 0.52:  # Only print promising results
                                print(f"[{len(results):3d}] AUC={auc:.4f} | {model_name:15} | {feat_name:15} | seq={seq_len:3d} | h={hidden:3d} | {loss_fn:5} | lr={lr}")
                        except Exception as e:
                            pass

#%% Results Analysis
print("\n" + "="*80)
print("TOP 20 RESULTS")
print("="*80)

results_df = pd.DataFrame(results)
results_df = results_df.sort_values('auc', ascending=False)

print(results_df.head(20).to_string(index=False))

#%% Best Model Deep Dive
if len(results_df) > 0:
    best = results_df.iloc[0]
    print("\n" + "="*80)
    print(f"BEST MODEL DETAILS")
    print("="*80)
    print(f"Model: {best['model']}")
    print(f"Features: {best['features']} ({best['n_features']} dims)")
    print(f"Seq Length: {best['seq_len']}")
    print(f"Hidden: {best['hidden']}")
    print(f"Loss: {best['loss']}")
    print(f"LR: {best['lr']}")
    print(f"AUC: {best['auc']:.4f}")
    print(f"Accuracy: {best['acc']:.4f}")
    print(f"Edge over random: {best['edge']:.2f}%")
    
    # Retrain best model and analyze
    print("\n--- Retraining best model for detailed analysis ---")
    
    feat_cols = FEATURE_SETS[best['features']]
    X, y, profits, valid_cols = extract_sequences(df, int(best['seq_len']), feat_cols, CLIP_TRADES)
    split_idx = int(len(X) * 0.8)
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]
    profits_val = profits[split_idx:]
    
    scaler = RobustScaler()
    n_train, sl, nf = X_train.shape
    X_train = scaler.fit_transform(X_train.reshape(-1, nf)).reshape(n_train, sl, nf)
    X_val = scaler.transform(X_val.reshape(-1, nf)).reshape(len(X_val), sl, nf)
    X_train = np.clip(X_train, -5, 5)
    X_val = np.clip(X_val, -5, 5)
    
    model_classes = {
        'SimpleLSTM': SimpleLSTM,
        'AttentionLSTM': AttentionLSTM,
        'BiLSTM': BiLSTM,
        'TCN': TCN,
        'Transformer': TransformerModel,
    }
    
    train_ds = TradeDataset(X_train, y_train)
    val_ds = TradeDataset(X_val, y_val)
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)
    
    model = model_classes[best['model']](len(valid_cols), int(best['hidden']), 2, 0.3).to(DEVICE)
    auc, preds, targets = train_model(model, train_loader, val_loader, epochs=50, lr=best['lr'], loss_fn=best['loss'])
    
    preds = np.array(preds)
    
    print(f"\nPrediction distribution:")
    print(f"  Min: {preds.min():.3f}, Max: {preds.max():.3f}, Mean: {preds.mean():.3f}, Std: {preds.std():.3f}")
    
    print(f"\nCalibration & P&L analysis:")
    for thresh in [0.4, 0.45, 0.5, 0.55, 0.6, 0.65, 0.7]:
        mask = preds > thresh
        if mask.sum() > 10:
            wr = y_val[mask].mean()
            avg_profit = profits_val[mask].mean()
            print(f"  P>{thresh:.2f}: {mask.sum():4d} trades | WR: {wr:.3f} | Avg Profit: {avg_profit*100:.3f}%")

#%% Save Best Model Config
if len(results_df) > 0:
    best_config = results_df.iloc[0].to_dict()
    import json
    with open('/allah/blue/ft/ml/best_config.json', 'w') as f:
        json.dump(best_config, f, indent=2, default=str)
    print(f"\nBest config saved to /allah/blue/ft/ml/best_config.json")

print("\n" + "="*80)
print("EXPERIMENT COMPLETE")
print("="*80)
