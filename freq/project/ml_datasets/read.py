# %% [CELL 1: Load Dataset and Basic Info]
import pandas as pd
import numpy as np

# Load the ML dataset
df = pd.read_feather('/allah/data/ml/atr_tp-1124-2038.feather')

# Basic info
print(f"Dataset shape: {df.shape}")
print(f"Total rows: {len(df)}")
print(f"\nColumns ({len(df.columns)}):")
print(df.columns.tolist())


# %% [CELL 2: Trade Analysis and Statistics]
# Trade analysis
trades_mask = df['profit_ratio'].notna()
df_trades = df[trades_mask]

print(f"Total candles: {len(df)}")
print(f"Candles with trades: {trades_mask.sum()}")
print(f"Candles without trades: {(~trades_mask).sum()}")

print("\nTrade Statistics:")
print(f"Total trades: {len(df_trades)}")
print(f"Profitable trades: {(df_trades['profit_ratio'] > 0).sum()}")
print(f"Losing trades: {(df_trades['profit_ratio'] < 0).sum()}")
print(f"\nProfit ratio - Mean: {df_trades['profit_ratio'].mean():.4f}")
print(f"Profit ratio - Median: {df_trades['profit_ratio'].median():.4f}")
print(f"Profit ratio - Std: {df_trades['profit_ratio'].std():.4f}")
print(f"Profit ratio - Min: {df_trades['profit_ratio'].min():.4f}")
print(f"Profit ratio - Max: {df_trades['profit_ratio'].max():.4f}")

print("\nTrade rows:")
display(df_trades.head(10))

# %% [CELL 3: Add Technical Indicators (33 indicators) - Optimized for 5s Timeframe]
import talib as ta

print("=" * 80)
print("CALCULATING 33 TECHNICAL INDICATORS")
print("Optimized for 5-SECOND TIMEFRAME Trading")
print("=" * 80)

print("\n⚠️  IMPORTANT: Timeframe Considerations for 5s Trading")
print("─" * 80)
print("Current timeframe: 5 seconds per candle")
print("\nPeriod translations to actual time:")
print("  • Period 14 = 70 seconds (1.17 minutes)")
print("  • Period 20 = 100 seconds (1.67 minutes)")
print("  • Period 50 = 250 seconds (4.17 minutes)")
print("  • Period 100 = 500 seconds (8.33 minutes)")
print("\nFor ultra-short timeframes (5s), indicators need faster periods!")
print("Adjusted periods for better responsiveness on 5s charts.")
print("=" * 80)

# Make a copy to avoid modifying original
df_features = df.copy()

# =============================================================================
# 1. TREND INDICATORS (12 indicators)
# Purpose: Identify market direction and trend strength
# Optimized for 5s timeframe - Faster periods for quick reactions
# =============================================================================
print("\n📈 1. TREND INDICATORS (12 indicators)")
print("   Purpose: Identify market direction, trend strength, and potential reversals")
print("   ⚡ Adjusted for 5s timeframe - Using faster periods")

# Moving Averages - Optimized for 5s
print("   • EMAs (Exponential Moving Averages) - React faster to price changes")
df_features['ema_5'] = ta.EMA(df['close'], timeperiod=5)     # Very short: 25s
df_features['ema_12'] = ta.EMA(df['close'], timeperiod=12)   # Short: 1 min
df_features['ema_30'] = ta.EMA(df['close'], timeperiod=30)   # Medium: 2.5 min

print("   • SMAs (Simple Moving Averages) - Smoother, less reactive")
df_features['sma_6'] = ta.SMA(df['close'], timeperiod=6)     # Short: 30s
df_features['sma_18'] = ta.SMA(df['close'], timeperiod=18)   # Medium: 1.5 min
df_features['sma_60'] = ta.SMA(df['close'], timeperiod=60)   # Long: 5 min

# MACD - Trend following momentum (kept proportional)
print("   • MACD (Moving Average Convergence Divergence) - Trend + Momentum")
macd, macd_signal, macd_hist = ta.MACD(df['close'], fastperiod=6, slowperiod=13, signalperiod=5)
df_features['macd'] = macd              # Difference between fast and slow EMA
df_features['macd_signal'] = macd_signal # Signal line (EMA of MACD)
df_features['macd_hist'] = macd_hist    # Histogram (MACD - Signal)
# Adjusted: 6,13,5 instead of standard 12,26,9 for 5s timeframe

# ADX - Trend Strength (not direction)
print("   • ADX (Average Directional Index) - Measures trend strength")
df_features['adx'] = ta.ADX(df['high'], df['low'], df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14 for 5s timeframe
# ADX > 25: Strong trend | ADX < 20: Weak/no trend

# Parabolic SAR - Trend following with stop levels
print("   • SAR (Parabolic SAR) - Stop and Reverse, trend following")
df_features['sar'] = ta.SAR(df['high'], df['low'], acceleration=0.04, maximum=0.4)
# Adjusted: Faster acceleration for 5s timeframe (0.04 vs 0.02)
# SAR below price: Uptrend | SAR above price: Downtrend

# APO - Similar to MACD but uses absolute values
print("   • APO (Absolute Price Oscillator) - Difference between fast/slow MA")
df_features['apo'] = ta.APO(df['close'], fastperiod=6, slowperiod=13)
# Adjusted: 6,13 instead of 12,26 for 5s timeframe

print("   ✓ Trend indicators calculated")

# =============================================================================
# 2. MOMENTUM INDICATORS (6 indicators)
# Purpose: Measure speed and strength of price movements
# Optimized for 5s timeframe - More responsive periods
# =============================================================================
print("\n⚡ 2. MOMENTUM INDICATORS (6 indicators)")
print("   Purpose: Measure the speed and strength of price movements")
print("   ⚡ Adjusted for 5s timeframe - Faster response")

print("   • RSI (Relative Strength Index) - Overbought/Oversold momentum")
df_features['rsi_7'] = ta.RSI(df['close'], timeperiod=7)   # Adjusted: 35s (fast)
df_features['rsi_14'] = ta.RSI(df['close'], timeperiod=14) # Adjusted: 70s (medium)
# RSI > 70: Overbought | RSI < 30: Oversold
# Note: On 5s, may need to adjust thresholds (e.g., >80/<20)

print("   • ROC (Rate of Change) - Percentage price change")
df_features['roc'] = ta.ROC(df['close'], timeperiod=5)
# Adjusted: 5 periods (25s) instead of 10 for quick reactions
# Positive: Upward momentum | Negative: Downward momentum

print("   • Momentum - Absolute price change")
df_features['momentum'] = ta.MOM(df['close'], timeperiod=5)
# Adjusted: 5 periods (25s) for fast momentum detection
# Similar to ROC but absolute difference

print("   • CMO (Chande Momentum Oscillator) - Momentum strength")
df_features['cmo'] = ta.CMO(df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14
# Range: -100 to +100 | >50: Strong up | <-50: Strong down

print("   • TRIX (Triple Exponential Average) - Smoothed momentum")
df_features['trix'] = ta.TRIX(df['close'], timeperiod=15)
# Adjusted: 15 periods (75s) instead of 30 for 5s timeframe
# Shows rate of change of triple smoothed EMA

print("   ✓ Momentum indicators calculated")

# =============================================================================
# 3. VOLATILITY INDICATORS (4 indicators)
# Purpose: Measure market volatility and potential breakouts
# Optimized for 5s timeframe - Critical for scalping
# =============================================================================
print("\n💥 3. VOLATILITY INDICATORS (4 indicators)")
print("   Purpose: Measure market volatility, price range, and potential breakouts")
print("   ⚡ Adjusted for 5s timeframe - Essential for scalping")

print("   • ATR (Average True Range) - Volatility/Range measurement")
df_features['atr'] = ta.ATR(df['high'], df['low'], df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14 for faster volatility detection
# Higher ATR: More volatile | Lower ATR: Less volatile
# CRITICAL for 5s: Use ATR for position sizing and stop-loss placement

print("   • Bollinger Bands - Price envelope with standard deviations")
bb_upper, bb_middle, bb_lower = ta.BBANDS(df['close'], timeperiod=12, nbdevup=2, nbdevdn=2)
df_features['bb_upper'] = bb_upper   # Upper band (2 std above MA)
df_features['bb_middle'] = bb_middle # Middle band (12-period SMA = 1 min)
df_features['bb_lower'] = bb_lower   # Lower band (2 std below MA)
# Adjusted: 12 periods (1 min) instead of 20 for 5s timeframe
# Price near upper: Potential overbought | Price near lower: Potential oversold
# Band width: Volatility indicator (tight = low vol, wide = high vol)
# On 5s: Expect frequent touches of bands (normal behavior)

print("   ✓ Volatility indicators calculated")

# =============================================================================
# 4. OSCILLATORS (5 indicators)
# Purpose: Identify overbought/oversold conditions and potential reversals
# Optimized for 5s timeframe - More sensitive thresholds needed
# =============================================================================
print("\n🔄 4. OSCILLATORS (5 indicators)")
print("   Purpose: Identify overbought/oversold conditions and potential reversals")
print("   ⚡ Adjusted for 5s timeframe - May need wider thresholds (e.g., 85/15)")

print("   • Stochastic Oscillator - Momentum + Overbought/Oversold")
slowk, slowd = ta.STOCH(df['high'], df['low'], df['close'], 
                        fastk_period=7, slowk_period=3, slowd_period=3)
df_features['stoch_k'] = slowk # %K line (fast)
df_features['stoch_d'] = slowd # %D line (slow, signal)
# Adjusted: fastk=7 (35s) instead of 14 for 5s timeframe
# >80: Overbought | <20: Oversold | K crosses D: Potential signal
# Note: On 5s, may see frequent extreme readings (normal)

print("   • CCI (Commodity Channel Index) - Price deviation from average")
df_features['cci'] = ta.CCI(df['high'], df['low'], df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14 for faster response
# >+100: Overbought | <-100: Oversold (on 5s, may need +/-150)

print("   • Williams %R - Similar to Stochastic")
df_features['willr'] = ta.WILLR(df['high'], df['low'], df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14
# Range: 0 to -100 | >-20: Overbought | <-80: Oversold

print("   • Ultimate Oscillator - Multi-timeframe oscillator")
df_features['ultosc'] = ta.ULTOSC(df['high'], df['low'], df['close'])
# Default periods (7,14,28) are actually reasonable for 5s
# Combines 35s, 70s, 140s timeframes | >70: Overbought | <30: Oversold

print("   ✓ Oscillator indicators calculated")

# =============================================================================
# 5. VOLUME INDICATORS (2 indicators)
# Purpose: Confirm trends and detect divergences using volume
# Note: Volume on 5s may be erratic - use with caution
# =============================================================================
print("\n📊 5. VOLUME INDICATORS (2 indicators)")
print("   Purpose: Confirm price movements and detect divergences using volume")
print("   ⚠️  WARNING: Volume can be erratic on 5s timeframe")

print("   • OBV (On Balance Volume) - Volume-based momentum")
df_features['obv'] = ta.OBV(df['close'], df['volume'])
# No period adjustment needed (cumulative indicator)
# Rising OBV: Buying pressure | Falling OBV: Selling pressure
# Divergence from price: Potential reversal
# Note: On 5s, OBV changes rapidly - focus on short-term divergences

print("   • MFI (Money Flow Index) - Volume-weighted RSI")
df_features['mfi'] = ta.MFI(df['high'], df['low'], df['close'], df['volume'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14 for 5s timeframe
# >80: Overbought | <20: Oversold | Uses both price and volume
# On 5s: May see more extreme readings due to volume spikes

print("   ✓ Volume indicators calculated")

# =============================================================================
# 6. DIRECTIONAL INDICATORS (4 indicators)
# Purpose: Determine trend direction and strength
# Optimized for 5s timeframe - Quick direction changes
# =============================================================================
print("\n🧭 6. DIRECTIONAL/STRENGTH INDICATORS (4 indicators)")
print("   Purpose: Determine trend direction, strength, and potential changes")
print("   ⚡ Adjusted for 5s timeframe - Faster trend detection")

print("   • +DI/-DI (Directional Indicators) - Trend direction components")
df_features['plus_di'] = ta.PLUS_DI(df['high'], df['low'], df['close'], timeperiod=7)
df_features['minus_di'] = ta.MINUS_DI(df['high'], df['low'], df['close'], timeperiod=7)
# Adjusted: 7 periods (35s) instead of 14 - matches ADX period
# +DI > -DI: Uptrend | -DI > +DI: Downtrend | Used with ADX
# On 5s: Expect frequent crossovers (normal for scalping)

print("   • Aroon Indicators - Time since highs/lows")
aroon_down, aroon_up = ta.AROON(df['high'], df['low'], timeperiod=10)
df_features['aroon_up'] = aroon_up     # Time since highest high
df_features['aroon_down'] = aroon_down # Time since lowest low
# Adjusted: 10 periods (50s) instead of 14 for 5s timeframe
# Aroon Up > 70 & Down < 30: Strong uptrend
# Aroon Down > 70 & Up < 30: Strong downtrend
# On 5s: Useful for detecting quick reversals

print("   ✓ Directional indicators calculated")

# =============================================================================
# SUMMARY OF ALL INDICATORS
# =============================================================================
new_features = [col for col in df_features.columns if col not in df.columns]

print("\n" + "=" * 80)
print("INDICATOR SUMMARY")
print("=" * 80)
print(f"Total indicators added: {len(new_features)}")
print(f"\nBreakdown by category (⚡ 5s-optimized periods):")
print(f"  📈 Trend Indicators:       12 (ema_5,12,30 | sma_6,18,60 | MACD | ADX | SAR | APO)")
print(f"  ⚡ Momentum Indicators:     6 (rsi_7,14 | ROC | Momentum | CMO | TRIX)")
print(f"  💥 Volatility Indicators:   4 (ATR | Bollinger Bands x3)")
print(f"  🔄 Oscillators:             5 (Stochastic x2 | CCI | WillR | UltOsc)")
print(f"  📊 Volume Indicators:       2 (OBV | MFI)")
print(f"  🧭 Directional Indicators:  4 (+DI | -DI | Aroon x2)")
print(f"  {'─' * 40}")
print(f"  Total Expected:            33 indicators")
print(f"  Actual Count:              {len(new_features)} indicators")

print(f"\n✓ Dataset shape with indicators: {df_features.shape}")

# Check for NaN values
print(f"\n" + "=" * 80)
print("DATA QUALITY CHECK")
print("=" * 80)
nan_summary = df_features[new_features].isna().sum()
nan_indicators = nan_summary[nan_summary > 0]

if len(nan_indicators) > 0:
    print(f"⚠ Indicators with NaN values:")
    for indicator, count in nan_indicators.items():
        pct = (count / len(df_features)) * 100
        print(f"  • {indicator}: {count} ({pct:.2f}%)")
    print(f"\nNote: NaN values are normal for indicators at the start of the dataset")
    print(f"      (due to lookback periods). Will be handled in scaling step.")
else:
    print("✓ No NaN values found in indicators!")

# Show sample data organized by category
print(f"\n" + "=" * 80)
print("SAMPLE DATA (First 5 rows)")
print("=" * 80)

# Show a few indicators from each category (with 5s-optimized names)
sample_indicators = [
    'date', 'close',
    'ema_12', 'macd',            # Trend
    'rsi_7', 'momentum',         # Momentum  
    'atr', 'bb_upper',           # Volatility
    'stoch_k', 'cci',            # Oscillators
    'obv', 'mfi',                # Volume
    'plus_di', 'aroon_up'        # Directional
]
sample_indicators = [col for col in sample_indicators if col in df_features.columns]
display(df_features[sample_indicators].head(5))

print("\n✓ All 33 technical indicators successfully calculated!")
print("=" * 80)

# =============================================================================
# SUMMARY: 5-Second Timeframe Adjustments
# =============================================================================
print("\n" + "=" * 80)
print("📋 SUMMARY OF ADJUSTMENTS FOR 5-SECOND TIMEFRAME")
print("=" * 80)

print("\n🔧 Period Adjustments Made:")
print("─" * 80)
print("Indicator         Variable Names    Standard → 5s     Actual Time")
print("─" * 80)
print("RSI              rsi_7, rsi_14      14,21 → 7,14      35s, 70s")
print("EMAs             ema_5,12,30        9,20,50 → 5,12,30 25s, 1m, 2.5m")
print("SMAs             sma_6,18,60        10,30,100→6,18,60 30s, 1.5m, 5m")
print("MACD             macd,signal,hist   12,26,9 → 6,13,5  30s, 65s, 25s")
print("ATR              atr                14 → 7            35 seconds")
print("Bollinger Bands  bb_upper,mid,low   20 → 12           1 minute")
print("ADX              adx                14 → 7            35 seconds")
print("Stochastic      stoch_k, stoch_d   14 → 7            35 seconds")
print("CCI              cci                14 → 7            35 seconds")
print("Williams %R      willr              14 → 7            35 seconds")
print("MFI              mfi                14 → 7            35 seconds")
print("ROC              roc                10 → 5            25 seconds")
print("Momentum         momentum           10 → 5            25 seconds")
print("CMO              cmo                14 → 7            35 seconds")
print("TRIX             trix               30 → 15           75 seconds")
print("+DI/-DI          plus_di,minus_di   14 → 7            35 seconds")
print("Aroon            aroon_up,down      14 → 10           50 seconds")
print("Parabolic SAR    sar                accel 0.02→0.04   Faster")
print("APO              apo                12,26 → 6,13      30s, 65s")
print("─" * 80)
print("\n✓ All variable names now match their actual periods!")

print("\n⚠️  CRITICAL CONSIDERATIONS FOR 5-SECOND TRADING:")
print("─" * 80)
print("1. NOISE LEVEL:")
print("   • 5s charts are VERY noisy - many false signals expected")
print("   • Indicators will show extreme readings more frequently")
print("   • Use multiple confirmations before entering trades")
print("\n2. OVERBOUGHT/OVERSOLD THRESHOLDS:")
print("   • Standard thresholds (70/30, 80/20) may be too sensitive")
print("   • Consider using wider thresholds: RSI 85/15, CCI ±150")
print("   • Expect oscillators to stay in extreme zones longer")
print("\n3. VOLUME INDICATORS:")
print("   • Volume can be erratic on 5s timeframe")
print("   • Large spikes common (single market orders)")
print("   • Focus on volume trends, not absolute values")
print("\n4. TREND INDICATORS:")
print("   • Trends change VERY quickly on 5s")
print("   • MAs will have frequent crossovers (normal)")
print("   • Consider price action over indicators for trend")
print("\n5. VOLATILITY (ATR):")
print("   • ATR is CRITICAL for 5s scalping")
print("   • Use for position sizing and stop-loss placement")
print("   • Expect ATR to spike during news/events")
print("\n6. FEATURE ENGINEERING TIPS:")
print("   • Create indicator COMBINATIONS (e.g., RSI + MACD alignment)")
print("   • Use indicator DIVERGENCES (price vs RSI/OBV)")
print("   • Consider indicator VELOCITY (rate of change of RSI)")
print("   • Add price action features (candle patterns, wicks)")
print("\n7. EXECUTION:")
print("   • Execution speed is EVERYTHING on 5s")
print("   • Slippage can eat profits quickly")
print("   • Use limit orders when possible")
print("   • Monitor spread closely")
print("\n8. RECOMMENDED INDICATOR FOCUS:")
print("   • Primary: ATR (volatility), rsi_7 (fast momentum), MACD (trend)")
print("   • Secondary: stoch_k/d, bb_upper/lower, plus_di/minus_di")
print("   • Medium: ema_5,12 (fast MAs), rsi_14, cci, willr")
print("   • Less useful: sma_60 (too slow), ultosc (lagging)")
print("   • Avoid: Single indicator values without context or combinations")
print("=" * 80)

print("\n💡 PROFESSIONAL TIP:")
print("   For 5s trading, PRICE ACTION + MOMENTUM indicators work best.")
print("   Trend indicators lag too much. Focus on:")
print("   • Quick momentum shifts (rsi_7, stoch_k)")
print("   • Volatility expansion (atr, bb_upper-bb_lower width)")
print("   • Volume spikes (obv, mfi)")
print("   • Support/resistance bounces (combine with indicators)")
print("   • Fast trend confirmation (ema_5 vs ema_12 crossovers)")
print("=" * 80)

# %% [CELL 4: Create Binary Labels and Filter for Trades Only]
print("="*80)
print("CREATING BINARY LABELS FOR CLASSIFICATION")
print("="*80)

# Create binary label: 1 if profitable (profit_ratio > 0), 0 if loss (profit_ratio <= 0)
df_features['is_profitable'] = (df_features['profit_ratio'] > 0).astype(int)

# Show distribution before filtering
print(f"\nTotal rows (all candles): {len(df_features)}")
print(f"Rows with trades: {df_features['profit_ratio'].notna().sum()}")
print(f"Rows without trades (will be removed): {df_features['profit_ratio'].isna().sum()}")

# Filter to keep only rows with actual trades (profit_ratio not NaN)
df_features_trades = df_features[df_features['profit_ratio'].notna()].copy()

print(f"\n✓ Filtered dataset shape: {df_features_trades.shape}")
print(f"\nBinary Label Distribution:")
print(f"  Profitable trades (label=1): {(df_features_trades['is_profitable'] == 1).sum()} ({(df_features_trades['is_profitable'] == 1).sum() / len(df_features_trades) * 100:.1f}%)")
print(f"  Loss trades (label=0):       {(df_features_trades['is_profitable'] == 0).sum()} ({(df_features_trades['is_profitable'] == 0).sum() / len(df_features_trades) * 100:.1f}%)")

print(f"\nProfit Ratio Statistics for Each Class:")
print(f"  Profitable trades (label=1):")
print(f"    Mean profit_ratio: {df_features_trades[df_features_trades['is_profitable'] == 1]['profit_ratio'].mean():.4f}")
print(f"    Min:  {df_features_trades[df_features_trades['is_profitable'] == 1]['profit_ratio'].min():.4f}")
print(f"    Max:  {df_features_trades[df_features_trades['is_profitable'] == 1]['profit_ratio'].max():.4f}")
print(f"\n  Loss trades (label=0):")
print(f"    Mean profit_ratio: {df_features_trades[df_features_trades['is_profitable'] == 0]['profit_ratio'].mean():.4f}")
print(f"    Min:  {df_features_trades[df_features_trades['is_profitable'] == 0]['profit_ratio'].min():.4f}")
print(f"    Max:  {df_features_trades[df_features_trades['is_profitable'] == 0]['profit_ratio'].max():.4f}")

print("\nSample of labeled data:")
display(df_features_trades[['date', 'close', 'profit_ratio', 'is_profitable']].head(10))

# Update df_features to use only trades for subsequent cells
df_features = df_features_trades

# %% [CELL 5: Feature Scaling (StandardScaler & RobustScaler)]
# Scale features for machine learning
from sklearn.preprocessing import StandardScaler, RobustScaler
import numpy as np

print("Scaling features for machine learning...")

# Define ONLY the technical indicators to be scaled and used as features (33 total)
# Organized by category (matching CELL 3 organization)
# ⚡ Updated names to match actual 5s-optimized periods
indicator_columns = [
    # 1. TREND INDICATORS (12)
    'ema_5', 'ema_12', 'ema_30',                    # EMAs (3) - Optimized for 5s
    'sma_6', 'sma_18', 'sma_60',                    # SMAs (3) - Optimized for 5s
    'macd', 'macd_signal', 'macd_hist',             # MACD (3) - 6,13,5 periods
    'adx',                                           # ADX - trend strength (1) - 7 period
    'sar',                                           # Parabolic SAR (1) - accel 0.04
    'apo',                                           # APO (1) - 6,13 periods
    
    # 2. MOMENTUM INDICATORS (6)
    'rsi_7', 'rsi_14',                              # RSI (2) - Optimized for 5s
    'roc',                                           # Rate of Change (1) - 5 period
    'momentum',                                      # Momentum (1) - 5 period
    'cmo',                                           # Chande Momentum (1) - 7 period
    'trix',                                          # TRIX (1) - 15 period
    
    # 3. VOLATILITY INDICATORS (4)
    'atr',                                           # Average True Range (1) - 7 period
    'bb_upper', 'bb_middle', 'bb_lower',            # Bollinger Bands (3) - 12 period
    
    # 4. OSCILLATORS (5)
    'stoch_k', 'stoch_d',                           # Stochastic (2) - 7,3,3 periods
    'cci',                                           # CCI (1) - 7 period
    'willr',                                         # Williams %R (1) - 7 period
    'ultosc',                                        # Ultimate Oscillator (1) - default
    
    # 5. VOLUME INDICATORS (2)
    'obv',                                           # On Balance Volume
    'mfi',                                           # Money Flow Index - 7 period
    
    # 6. DIRECTIONAL INDICATORS (4)
    'plus_di', 'minus_di',                          # Directional Indicators (2) - 7 period
    'aroon_up', 'aroon_down'                        # Aroon Indicators (2) - 10 period
]

# Total: 12 + 6 + 4 + 5 + 2 + 4 = 33 indicators
# All periods optimized for 5-second timeframe trading

# Only scale the indicator columns that exist in the dataframe
cols_to_scale = [col for col in indicator_columns if col in df_features.columns]

print(f"\nTotal indicator columns to scale: {len(cols_to_scale)}")
print(f"Columns to scale: {cols_to_scale}")

# Create a copy for scaled data
df_scaled = df_features.copy()

# Handle NaN values before scaling (forward fill then backward fill)
print("\nHandling NaN values...")
print(f"NaN count before: {df_scaled[cols_to_scale].isna().sum().sum()}")
df_scaled[cols_to_scale] = df_scaled[cols_to_scale].fillna(method='ffill').fillna(method='bfill')
print(f"NaN count after: {df_scaled[cols_to_scale].isna().sum().sum()}")

# Option 1: StandardScaler (mean=0, std=1) - good for most ML algorithms
scaler_standard = StandardScaler()
df_scaled[cols_to_scale] = scaler_standard.fit_transform(df_scaled[cols_to_scale])

print("\n✓ Features scaled using StandardScaler (mean=0, std=1)")

# Show statistics of scaled features
print("\nScaled features statistics:")
print(df_scaled[cols_to_scale].describe().loc[['mean', 'std', 'min', 'max']])

# Compare before and after scaling for sample indicator columns
# Note: close/volume are NOT scaled (not in indicator_columns), shown for comparison
comparison_cols = ['close', 'volume', 'rsi_7', 'macd', 'obv']
comparison_cols = [col for col in comparison_cols if col in df_scaled.columns]

print("\n" + "="*80)
print("BEFORE vs AFTER SCALING (first 5 rows):")
print("="*80)
for col in comparison_cols:
    is_scaled = col in cols_to_scale
    status = "SCALED" if is_scaled else "NOT SCALED"
    print(f"\n{col.upper()} ({status}):")
    print(f"  Original: {df_features[col].head().values}")
    print(f"  Scaled:   {df_scaled[col].head().values}")
    print(f"  Range: [{df_scaled[col].min():.3f}, {df_scaled[col].max():.3f}]")

# Create alternative scaled version with RobustScaler (more resistant to outliers)
df_scaled_robust = df_features.copy()
df_scaled_robust[cols_to_scale] = df_scaled_robust[cols_to_scale].fillna(method='ffill').fillna(method='bfill')

scaler_robust = RobustScaler()
df_scaled_robust[cols_to_scale] = scaler_robust.fit_transform(df_scaled_robust[cols_to_scale])

print("\n✓ Alternative: RobustScaler version also created (df_scaled_robust)")
print("  - RobustScaler uses median and IQR, better for data with outliers")

# Show final shapes
print("\n" + "="*80)
print("FINAL DATASETS:")
print("="*80)
print(f"df_features (original with indicators): {df_features.shape}")
print(f"df_scaled (StandardScaler):             {df_scaled.shape}")
print(f"df_scaled_robust (RobustScaler):        {df_scaled_robust.shape}")

# Display sample of scaled data
print("\nSample of scaled data:")
display(df_scaled[['date', 'close', 'volume', 'rsi_7', 'macd', 'atr']].head(10))

# %% [CELL 6: Train Classification Models to Predict Profitable Trades]
# Train multiple ML CLASSIFICATION models to predict is_profitable (binary label)
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import xgboost as xgb
import lightgbm as lgb
from datetime import datetime

print("="*80)
print("TRAINING CLASSIFICATION MODELS (Predict Profitable vs Loss)")
print("="*80)

# Prepare data for training
print("\nPreparing training data...")

# Define target column (binary label)
target_col = 'is_profitable'

# Use the same indicator columns we defined for scaling as our features
# Only include indicators that exist in the scaled dataframe
feature_cols = [col for col in indicator_columns if col in df_scaled.columns]
print(f"Total features (technical indicators): {len(feature_cols)}")
print(f"Features: {feature_cols}")

# All rows already have trades (filtered in CELL 4)
# Prepare X and y
X = df_scaled[feature_cols]
y = df_scaled[target_col]

print(f"\nFeature matrix shape: {X.shape}")
print(f"Target vector shape: {y.shape}")
print(f"\nClass distribution in full dataset:")
print(f"  Class 0 (Loss):       {(y == 0).sum()} ({(y == 0).sum() / len(y) * 100:.1f}%)")
print(f"  Class 1 (Profitable): {(y == 1).sum()} ({(y == 1).sum() / len(y) * 100:.1f}%)")

# Split data (80% train, 20% test) with time-based split
split_idx = int(len(X) * 0.8)
X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

print(f"\nTrain set: {len(X_train)} samples")
print(f"  Class 0: {(y_train == 0).sum()} | Class 1: {(y_train == 1).sum()}")
print(f"Test set:  {len(X_test)} samples")
print(f"  Class 0: {(y_test == 0).sum()} | Class 1: {(y_test == 1).sum()}")

# Define classification models to train
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42),
    'XGBoost': xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric='logloss'),
    'LightGBM': lgb.LGBMClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42, n_jobs=-1, verbose=-1),
    'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
    'Neural Network': MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42, early_stopping=True)
}

# Train and evaluate each model
results = {}

print("\n" + "="*80)
print("TRAINING MODELS")
print("="*80)

for name, model in models.items():
    print(f"\n{name}:")
    print("-" * 40)
    
    # Train
    start_time = datetime.now()
    model.fit(X_train, y_train)
    train_time = (datetime.now() - start_time).total_seconds()
    
    # Predict
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    
    # Get probability predictions for ROC-AUC (if available)
    try:
        y_pred_proba_test = model.predict_proba(X_test)[:, 1]
        roc_auc = roc_auc_score(y_test, y_pred_proba_test)
    except:
        roc_auc = None
    
    # Calculate classification metrics
    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    train_precision = precision_score(y_train, y_pred_train, zero_division=0)
    test_precision = precision_score(y_test, y_pred_test, zero_division=0)
    train_recall = recall_score(y_train, y_pred_train, zero_division=0)
    test_recall = recall_score(y_test, y_pred_test, zero_division=0)
    train_f1 = f1_score(y_train, y_pred_train, zero_division=0)
    test_f1 = f1_score(y_test, y_pred_test, zero_division=0)
    
    results[name] = {
        'model': model,
        'train_time': train_time,
        'train_acc': train_acc,
        'test_acc': test_acc,
        'train_precision': train_precision,
        'test_precision': test_precision,
        'train_recall': train_recall,
        'test_recall': test_recall,
        'train_f1': train_f1,
        'test_f1': test_f1,
        'roc_auc': roc_auc,
        'predictions': y_pred_test,
        'conf_matrix': confusion_matrix(y_test, y_pred_test)
    }
    
    print(f"  Training time: {train_time:.2f}s")
    print(f"  Train Accuracy: {train_acc:.4f} | Test Accuracy: {test_acc:.4f}")
    print(f"  Train Precision: {train_precision:.4f} | Test Precision: {test_precision:.4f}")
    print(f"  Train Recall:    {train_recall:.4f} | Test Recall:    {test_recall:.4f}")
    print(f"  Train F1:        {train_f1:.4f} | Test F1:        {test_f1:.4f}")
    if roc_auc:
        print(f"  ROC-AUC Score:   {roc_auc:.4f}")

# Summary comparison
print("\n" + "="*80)
print("MODEL COMPARISON (sorted by Test F1 Score)")
print("="*80)

comparison_df = pd.DataFrame({
    'Model': list(results.keys()),
    'Test Accuracy': [r['test_acc'] for r in results.values()],
    'Test Precision': [r['test_precision'] for r in results.values()],
    'Test Recall': [r['test_recall'] for r in results.values()],
    'Test F1': [r['test_f1'] for r in results.values()],
    'ROC-AUC': [r['roc_auc'] if r['roc_auc'] else 0 for r in results.values()],
    'Train Time (s)': [r['train_time'] for r in results.values()]
})

comparison_df = comparison_df.sort_values('Test F1', ascending=False)
display(comparison_df)

# Find best model
best_model_name = comparison_df.iloc[0]['Model']
best_model_results = results[best_model_name]

print(f"\n🏆 Best Model: {best_model_name}")
print(f"   Test Accuracy:  {best_model_results['test_acc']:.4f}")
print(f"   Test Precision: {best_model_results['test_precision']:.4f}")
print(f"   Test Recall:    {best_model_results['test_recall']:.4f}")
print(f"   Test F1 Score:  {best_model_results['test_f1']:.4f}")
if best_model_results['roc_auc']:
    print(f"   ROC-AUC Score:  {best_model_results['roc_auc']:.4f}")

# Confusion Matrix
print(f"\n📊 Confusion Matrix ({best_model_name}):")
conf_mat = best_model_results['conf_matrix']
print(f"\n                Predicted")
print(f"              Loss (0)  Win (1)")
print(f"Actual Loss    {conf_mat[0][0]:6d}    {conf_mat[0][1]:6d}")
print(f"Actual Win     {conf_mat[1][0]:6d}    {conf_mat[1][1]:6d}")

# Feature importance (for tree-based models)
if hasattr(best_model_results['model'], 'feature_importances_'):
    print(f"\n📊 Top 15 Important Features ({best_model_name}):")
    importances = best_model_results['model'].feature_importances_
    feature_importance_df = pd.DataFrame({
        'Feature': feature_cols,
        'Importance': importances
    }).sort_values('Importance', ascending=False)
    
    display(feature_importance_df.head(15))

# Prediction analysis
print("\n" + "="*80)
print("PREDICTION ANALYSIS (Best Model)")
print("="*80)

pred_analysis = pd.DataFrame({
    'Actual': y_test.values,
    'Predicted': best_model_results['predictions'],
    'Correct': y_test.values == best_model_results['predictions']
})

print("\nPrediction Statistics:")
print(f"  Total predictions:     {len(pred_analysis)}")
print(f"  Correct predictions:   {pred_analysis['Correct'].sum()} ({pred_analysis['Correct'].sum() / len(pred_analysis) * 100:.1f}%)")
print(f"  Incorrect predictions: {(~pred_analysis['Correct']).sum()} ({(~pred_analysis['Correct']).sum() / len(pred_analysis) * 100:.1f}%)")

print("\nBreakdown by Actual Class:")
print(f"  Actual Loss (0): Correct={((pred_analysis['Actual'] == 0) & pred_analysis['Correct']).sum()}, "
      f"Incorrect={((pred_analysis['Actual'] == 0) & ~pred_analysis['Correct']).sum()}")
print(f"  Actual Win (1):  Correct={((pred_analysis['Actual'] == 1) & pred_analysis['Correct']).sum()}, "
      f"Incorrect={((pred_analysis['Actual'] == 1) & ~pred_analysis['Correct']).sum()}")

print("\nSample Predictions:")
display(pred_analysis.head(20))

print("\n" + "="*80)
print("CLASSIFICATION REPORT")
print("="*80)
print(classification_report(y_test, best_model_results['predictions'], 
                           target_names=['Loss (0)', 'Win (1)'], digits=4))




# %%
