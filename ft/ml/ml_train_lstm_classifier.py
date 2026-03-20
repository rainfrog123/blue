#!/usr/bin/env python3
"""
PyTorch LSTM for Trade Result Prediction

Predicts whether a trade will WIN or LOSE based on:
- Sequence of candles leading up to the signal
- Technical indicators and microstructure features
"""

import os
import glob
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
import talib as ta
from pathlib import Path


# ============================================================================
# Configuration
# ============================================================================

class Config:
    # Data
    data_dir = "/allah/data/ml"
    sequence_length = 60  # Look back 60 candles (5 minutes at 5s)
    
    # Model
    input_size = None  # Set dynamically based on features
    hidden_size = 128
    num_layers = 2
    dropout = 0.3
    bidirectional = True
    
    # Training
    batch_size = 64
    epochs = 100
    learning_rate = 1e-3
    weight_decay = 1e-5
    patience = 15  # Early stopping
    
    # Split ratios (temporal split)
    train_ratio = 0.7
    val_ratio = 0.15
    test_ratio = 0.15
    
    # Device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Output
    model_dir = "/allah/blue/ft/ml/models"


# ============================================================================
# Feature Engineering
# ============================================================================

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add technical features for LSTM input."""
    df = df.copy()
    o, h, l, c, v = df['open'], df['high'], df['low'], df['close'], df['volume']
    
    # === Price Returns ===
    for period in [1, 3, 6, 12, 24]:
        df[f'ret_{period}'] = c.pct_change(period) * 100
    
    # === Volatility ===
    df['range_pct'] = (h - l) / c * 100
    df['atr_6'] = ta.ATR(h, l, c, timeperiod=6)
    df['atr_14'] = ta.ATR(h, l, c, timeperiod=14)
    df['natr_6'] = ta.NATR(h, l, c, timeperiod=6)
    
    # === Volume ===
    df['vol_ma6'] = v.rolling(6).mean()
    df['vol_ratio'] = v / (df['vol_ma6'] + 1e-10)
    
    # === RSI ===
    df['rsi_6'] = ta.RSI(c, timeperiod=6)
    df['rsi_14'] = ta.RSI(c, timeperiod=14)
    
    # === MACD ===
    macd, macd_signal, macd_hist = ta.MACD(c, fastperiod=12, slowperiod=26, signalperiod=9)
    df['macd'] = macd
    df['macd_signal'] = macd_signal
    df['macd_hist'] = macd_hist
    
    # === Bollinger Bands ===
    bb_upper, bb_mid, bb_lower = ta.BBANDS(c, timeperiod=20, nbdevup=2, nbdevdn=2)
    df['bb_width'] = (bb_upper - bb_lower) / bb_mid
    df['bb_position'] = (c - bb_lower) / (bb_upper - bb_lower + 1e-10)
    
    # === Candle Structure ===
    df['body_pct'] = (c - o) / (o + 1e-10) * 100
    df['body_ratio'] = abs(c - o) / (h - l + 1e-10)
    df['upper_wick'] = (h - np.maximum(o, c)) / (h - l + 1e-10)
    df['lower_wick'] = (np.minimum(o, c) - l) / (h - l + 1e-10)
    df['close_position'] = (c - l) / (h - l + 1e-10)
    
    # === Momentum ===
    df['mom_6'] = ta.MOM(c, timeperiod=6)
    df['roc_6'] = ta.ROC(c, timeperiod=6)
    
    # === Tick Microstructure (if available) ===
    if 'open_count' in df.columns:
        df['tick_total'] = df['open_count'] + df['high_count'] + df['low_count'] + df['close_count']
        df['tick_imbalance'] = (df['high_count'] - df['low_count']) / (df['tick_total'] + 1e-10)
    
    # === Price vs Moving Averages ===
    df['ema_6'] = ta.EMA(c, timeperiod=6)
    df['ema_12'] = ta.EMA(c, timeperiod=12)
    df['price_vs_ema6'] = (c - df['ema_6']) / df['ema_6'] * 100
    df['price_vs_ema12'] = (c - df['ema_12']) / df['ema_12'] * 100
    
    return df


def get_feature_columns(df: pd.DataFrame) -> list:
    """Get list of feature columns for model input."""
    base_features = [
        'ret_1', 'ret_3', 'ret_6', 'ret_12', 'ret_24',
        'range_pct', 'atr_6', 'atr_14', 'natr_6',
        'vol_ratio',
        'rsi_6', 'rsi_14',
        'macd', 'macd_signal', 'macd_hist',
        'bb_width', 'bb_position',
        'body_pct', 'body_ratio', 'upper_wick', 'lower_wick', 'close_position',
        'mom_6', 'roc_6',
        'price_vs_ema6', 'price_vs_ema12'
    ]
    
    # Add tick features if available
    if 'tick_total' in df.columns:
        base_features.extend(['tick_total', 'tick_imbalance'])
    
    # Add strategy-specific features if available
    if 'tema' in df.columns:
        base_features.append('tema')
    if 'tema_slope' in df.columns:
        base_features.append('tema_slope')
    if 'trend_flip' in df.columns:
        base_features.append('trend_flip')
    
    return [f for f in base_features if f in df.columns]


# ============================================================================
# Dataset
# ============================================================================

class TradeSequenceDataset(Dataset):
    """Dataset for LSTM: sequences of candles leading to trade signals."""
    
    def __init__(self, sequences: np.ndarray, labels: np.ndarray):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.FloatTensor(labels)
    
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]


def create_sequences(df: pd.DataFrame, feature_cols: list, seq_length: int) -> tuple:
    """Create sequences for trades only."""
    # Handle different label formats
    if 'label' in df.columns:
        # New format with is_winner column
        trade_mask = df['label'].notna()
        is_winner = df['is_winner'] == 1
    elif 'profit_ratio' in df.columns:
        # Old format - use profit_ratio or exit_reason
        trade_mask = df['profit_ratio'].notna()
        # Define win as: roi exit OR positive profit
        if 'exit_reason' in df.columns:
            is_winner = (df['exit_reason'] == 'roi') | (df['profit_ratio'] > 0)
        else:
            is_winner = df['profit_ratio'] > 0
    else:
        return np.array([]), np.array([])
    
    trade_indices = df.index[trade_mask].tolist()
    
    if not trade_indices:
        return np.array([]), np.array([])
    
    # Prepare feature matrix
    features = df[feature_cols].values
    labels = is_winner.astype(float).values
    
    sequences = []
    seq_labels = []
    
    for idx in trade_indices:
        # Get position in dataframe
        pos = df.index.get_loc(idx)
        
        # Need enough history
        if pos < seq_length:
            continue
        
        # Extract sequence (seq_length candles before the signal)
        seq = features[pos - seq_length:pos]
        
        # Check for NaN
        if np.isnan(seq).any():
            continue
        
        sequences.append(seq)
        seq_labels.append(labels[pos])
    
    return np.array(sequences), np.array(seq_labels)


# ============================================================================
# Model
# ============================================================================

class TradeLSTM(nn.Module):
    """Bidirectional LSTM for trade prediction."""
    
    def __init__(self, input_size: int, hidden_size: int, num_layers: int, 
                 dropout: float, bidirectional: bool):
        super().__init__()
        
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.bidirectional = bidirectional
        self.num_directions = 2 if bidirectional else 1
        
        # LSTM layers
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=bidirectional
        )
        
        # Attention mechanism
        self.attention = nn.Sequential(
            nn.Linear(hidden_size * self.num_directions, hidden_size),
            nn.Tanh(),
            nn.Linear(hidden_size, 1)
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * self.num_directions, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        # x shape: (batch, seq_len, input_size)
        
        # LSTM forward
        lstm_out, _ = self.lstm(x)
        # lstm_out shape: (batch, seq_len, hidden_size * num_directions)
        
        # Attention weights
        attn_weights = self.attention(lstm_out)
        attn_weights = torch.softmax(attn_weights, dim=1)
        
        # Weighted sum of LSTM outputs
        context = torch.sum(attn_weights * lstm_out, dim=1)
        # context shape: (batch, hidden_size * num_directions)
        
        # Classification
        out = self.classifier(context)
        return out.squeeze(-1)


# ============================================================================
# Training
# ============================================================================

def train_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []
    
    for sequences, labels in loader:
        sequences = sequences.to(device)
        labels = labels.to(device)
        
        optimizer.zero_grad()
        outputs = model(sequences)
        loss = criterion(outputs, labels)
        
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        
        total_loss += loss.item()
        all_preds.extend((outputs > 0.5).cpu().numpy())
        all_labels.extend(labels.cpu().numpy())
    
    acc = accuracy_score(all_labels, all_preds)
    return total_loss / len(loader), acc


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0
    all_preds = []
    all_probs = []
    all_labels = []
    
    with torch.no_grad():
        for sequences, labels in loader:
            sequences = sequences.to(device)
            labels = labels.to(device)
            
            outputs = model(sequences)
            loss = criterion(outputs, labels)
            
            total_loss += loss.item()
            all_probs.extend(outputs.cpu().numpy())
            all_preds.extend((outputs > 0.5).cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    metrics = {
        'loss': total_loss / len(loader),
        'accuracy': accuracy_score(all_labels, all_preds),
        'precision': precision_score(all_labels, all_preds, zero_division=0),
        'recall': recall_score(all_labels, all_preds, zero_division=0),
        'f1': f1_score(all_labels, all_preds, zero_division=0),
    }
    
    if len(set(all_labels)) > 1:
        metrics['roc_auc'] = roc_auc_score(all_labels, all_probs)
    else:
        metrics['roc_auc'] = 0.0
    
    return metrics, np.array(all_preds), np.array(all_labels), np.array(all_probs)


# ============================================================================
# Main
# ============================================================================

def load_data(config: Config) -> pd.DataFrame:
    """Load and combine all ML datasets."""
    pattern = os.path.join(config.data_dir, "*.feather")
    files = glob.glob(pattern)
    
    if not files:
        raise FileNotFoundError(f"No feather files found in {config.data_dir}")
    
    print(f"Found {len(files)} dataset files")
    
    dfs = []
    for f in sorted(files):
        df = pd.read_feather(f)
        df['source_file'] = os.path.basename(f)
        dfs.append(df)
        
        # Count trades - handle both formats
        if 'label' in df.columns:
            trades = df['label'].notna().sum()
        elif 'profit_ratio' in df.columns:
            trades = df['profit_ratio'].notna().sum()
        else:
            trades = 0
        print(f"  {os.path.basename(f)}: {len(df)} candles, {trades} trades")
    
    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.sort_values('date').reset_index(drop=True)
    
    return combined


def main():
    config = Config()
    print(f"Device: {config.device}")
    print(f"Sequence length: {config.sequence_length}")
    
    # Load data
    print("\n=== Loading Data ===")
    df = load_data(config)
    trade_count = df['label'].notna().sum() if 'label' in df.columns else df['profit_ratio'].notna().sum()
    print(f"Total: {len(df)} candles, {trade_count} trades")
    
    # Feature engineering
    print("\n=== Feature Engineering ===")
    df = engineer_features(df)
    feature_cols = get_feature_columns(df)
    print(f"Features: {len(feature_cols)}")
    
    # Handle NaN and scale features
    df[feature_cols] = df[feature_cols].ffill().bfill()
    
    scaler = StandardScaler()
    df[feature_cols] = scaler.fit_transform(df[feature_cols])
    
    # Create sequences
    print("\n=== Creating Sequences ===")
    sequences, labels = create_sequences(df, feature_cols, config.sequence_length)
    
    if len(sequences) == 0:
        print("No valid sequences found!")
        return
    
    print(f"Sequences: {sequences.shape}")
    print(f"Labels: WIN={int(labels.sum())}, LOSE={int(len(labels) - labels.sum())}")
    
    # Temporal split
    n = len(sequences)
    train_end = int(n * config.train_ratio)
    val_end = int(n * (config.train_ratio + config.val_ratio))
    
    X_train, y_train = sequences[:train_end], labels[:train_end]
    X_val, y_val = sequences[train_end:val_end], labels[train_end:val_end]
    X_test, y_test = sequences[val_end:], labels[val_end:]
    
    print(f"\nSplits: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
    
    # Datasets and loaders
    train_dataset = TradeSequenceDataset(X_train, y_train)
    val_dataset = TradeSequenceDataset(X_val, y_val)
    test_dataset = TradeSequenceDataset(X_test, y_test)
    
    train_loader = DataLoader(train_dataset, batch_size=config.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config.batch_size)
    test_loader = DataLoader(test_dataset, batch_size=config.batch_size)
    
    # Model
    config.input_size = len(feature_cols)
    model = TradeLSTM(
        input_size=config.input_size,
        hidden_size=config.hidden_size,
        num_layers=config.num_layers,
        dropout=config.dropout,
        bidirectional=config.bidirectional
    ).to(config.device)
    
    print(f"\n=== Model ===")
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Parameters: {total_params:,}")
    
    # Class weights for imbalanced data
    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    pos_weight = torch.tensor([neg_count / (pos_count + 1e-10)]).to(config.device)
    print(f"Class weights: pos_weight={pos_weight.item():.2f} (WIN:{int(pos_count)}, LOSE:{int(neg_count)})")
    
    # Use weighted BCE loss
    def weighted_bce_loss(pred, target):
        weight = torch.where(target == 1, pos_weight, torch.ones_like(pos_weight))
        bce = nn.functional.binary_cross_entropy(pred, target, reduction='none')
        return (bce * weight).mean()
    
    criterion = weighted_bce_loss
    
    optimizer = torch.optim.AdamW(
        model.parameters(), 
        lr=config.learning_rate,
        weight_decay=config.weight_decay
    )
    
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='max', factor=0.5, patience=5
    )
    
    # Training loop
    print(f"\n=== Training ===")
    best_val_f1 = -1  # Start at -1 so first epoch always saves
    patience_counter = 0
    history = {'train_loss': [], 'val_loss': [], 'val_f1': []}
    
    # Save initial model
    os.makedirs(config.model_dir, exist_ok=True)
    
    for epoch in range(config.epochs):
        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, config.device)
        val_metrics, _, _, _ = evaluate(model, val_loader, criterion, config.device)
        
        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_metrics['loss'])
        history['val_f1'].append(val_metrics['f1'])
        
        scheduler.step(val_metrics['f1'])
        
        print(f"Epoch {epoch+1:3d} | Train Loss: {train_loss:.4f} | "
              f"Val Loss: {val_metrics['loss']:.4f} | Val F1: {val_metrics['f1']:.4f} | "
              f"Val Acc: {val_metrics['accuracy']:.4f}")
        
        # Early stopping
        if val_metrics['f1'] > best_val_f1:
            best_val_f1 = val_metrics['f1']
            patience_counter = 0
            
            # Save best model
            os.makedirs(config.model_dir, exist_ok=True)
            torch.save({
                'model_state_dict': model.state_dict(),
                'config': vars(config),
                'feature_cols': feature_cols,
                'scaler_mean': scaler.mean_,
                'scaler_scale': scaler.scale_,
            }, os.path.join(config.model_dir, 'best_lstm.pt'))
        else:
            patience_counter += 1
            if patience_counter >= config.patience:
                print(f"\nEarly stopping at epoch {epoch+1}")
                break
    
    # Load best model for evaluation
    checkpoint = torch.load(os.path.join(config.model_dir, 'best_lstm.pt'), weights_only=False)
    model.load_state_dict(checkpoint['model_state_dict'])
    
    # Test evaluation
    print(f"\n=== Test Results ===")
    test_metrics, test_preds, test_labels, test_probs = evaluate(
        model, test_loader, criterion, config.device
    )
    
    print(f"Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"Precision: {test_metrics['precision']:.4f}")
    print(f"Recall:    {test_metrics['recall']:.4f}")
    print(f"F1 Score:  {test_metrics['f1']:.4f}")
    print(f"ROC-AUC:   {test_metrics['roc_auc']:.4f}")
    
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(test_labels, test_preds)
    print(cm)
    
    print(f"\nClassification Report:")
    print(classification_report(test_labels, test_preds, target_names=['LOSE', 'WIN']))
    
    # Save results
    results = {
        'test_metrics': test_metrics,
        'history': history,
        'config': {k: str(v) if isinstance(v, (Path, torch.device)) else v 
                   for k, v in vars(config).items()},
        'feature_cols': feature_cols,
    }
    
    with open(os.path.join(config.model_dir, 'lstm_results.json'), 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nModel saved to: {config.model_dir}/best_lstm.pt")
    print(f"Results saved to: {config.model_dir}/lstm_results.json")


if __name__ == "__main__":
    main()
