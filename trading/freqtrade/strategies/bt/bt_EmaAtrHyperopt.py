from datetime import datetime
from pandas import DataFrame
import numpy as np
import pandas as pd
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy, DecimalParameter
from freqtrade.persistence import Trade

logger = logging.getLogger(__name__)

class EmaAtrHyperopt(IStrategy):
    """EMA crossover strategy with ATR-based stop-loss and take-profit."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 50
    
    # Fixed stoploss as fallback (will be overridden by custom_stoploss)
    stoploss = -0.05
    trailing_stop = False
    use_custom_stoploss = True
    use_custom_exit = True
    
    # Fixed parameters
    # EMA parameters
    fast_ema_period = 10
    slow_ema_period = 30
    
    # ATR parameters
    atr_period = 24
    
    # Hyperoptable parameters
    # Stop-Loss multiplier (k) - range adjusted for 5s timeframe
    # With ATR% around 0.0005 (0.05%), multiplier of 5-20 gives 0.25%-1% SL
    atr_sl_multiplier = DecimalParameter(5.0, 20.0, decimals=1, default=10.0, space="sell", optimize=True)
    
    # Take-Profit multiplier (r) - automatically set to 2x stop-loss
    @property
    def atr_tp_multiplier(self):
        return self.atr_sl_multiplier.value * 2

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate EMA and ATR indicators."""
        
        # Calculate EMAs
        dataframe['fast_ema'] = ta.EMA(dataframe['close'], timeperiod=self.fast_ema_period)
        dataframe['slow_ema'] = ta.EMA(dataframe['close'], timeperiod=self.slow_ema_period)
        
        # Calculate ATR as percentage of close price
        atr_raw = ta.ATR(dataframe, timeperiod=self.atr_period)
        dataframe['atr_pct'] = (atr_raw / dataframe['close'])  # ATR as percentage (e.g., 0.03 = 3%)
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Entry signals based on EMA crossovers."""
        
        # Get EMA values
        fast_ema = dataframe['fast_ema']
        slow_ema = dataframe['slow_ema']
        fast_ema_prev = fast_ema.shift(1)
        slow_ema_prev = slow_ema.shift(1)
        
        # Long signal: fast EMA crosses above slow EMA
        dataframe.loc[
            (fast_ema > slow_ema) & 
            (fast_ema_prev <= slow_ema_prev) &
            (dataframe['volume'] > 0),
            'enter_long'
        ] = 1
        
        # Short signal: fast EMA crosses below slow EMA
        dataframe.loc[
            (fast_ema < slow_ema) & 
            (fast_ema_prev >= slow_ema_prev) &
            (dataframe['volume'] > 0),
            'enter_short'
        ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Exit signals - uses custom_exit for ATR-based TP."""
        return dataframe

    def custom_stoploss(self, pair: str, trade: Trade, current_time: datetime,
                       current_rate: float, current_profit: float, after_fill: bool,
                       **kwargs) -> float | None:
        """
        Custom stoploss using ATR percentage.
        Stop-Loss = ATR% × k
        Minimum stoploss is 0.5% to prevent too tight stops on low volatility.
        """
            
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        last_candle = dataframe.iloc[-1].squeeze()
        
        atr_pct = last_candle['atr_pct']
        
        if pd.isna(atr_pct):
            return None
        
        # Calculate ATR-based stop distance as percentage
        # ATR is already normalized as percentage of price
        atr_stop_distance = atr_pct * self.atr_sl_multiplier.value
        
        # Apply minimum stoploss of 0.5% to prevent too tight stops
        min_stoploss = 0.003
        atr_stop_distance = max(atr_stop_distance, min_stoploss)
        
        if trade.is_short:
            # For shorts, positive stoploss (price goes up)
            return atr_stop_distance
        else:
            # For longs, negative stoploss (price goes down)
            return -atr_stop_distance

    def custom_exit(self, pair: str, trade: Trade, current_time: datetime,
                   current_rate: float, current_profit: float, **kwargs) -> str | None:
        """
        Custom exit using ATR percentage for take-profit.
        Take-Profit = ATR% × r (where r = k × 2)
        Minimum TP is 1.0% (2x minimum stoploss).
        """
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        last_candle = dataframe.iloc[-1].squeeze()
        
        atr_pct = last_candle['atr_pct']
        
        if pd.isna(atr_pct):
            return None
        
        # Calculate ATR-based take-profit distance
        # TP multiplier is automatically 2x the SL multiplier
        atr_tp_distance = atr_pct * self.atr_tp_multiplier
        
        # Apply minimum take-profit of 1.0% (2x minimum stoploss)
        min_tp = 0.01
        atr_tp_distance = max(atr_tp_distance, min_tp)
        
        if trade.is_short:
            # For shorts: exit when price drops enough
            if current_profit >= atr_tp_distance:
                return 'atr_tp_short'
        else:
            # For longs: exit when price rises enough
            if current_profit >= atr_tp_distance:
                return 'atr_tp_long'
        
        return None

    def leverage(self, pair: str, current_time: datetime, current_rate: float, 
                proposed_leverage: float, max_leverage: float, entry_tag: str | None, 
                side: str, **kwargs) -> float:
        """Use 1x leverage."""
        return 1