from datetime import datetime
from pandas import DataFrame
import numpy as np
import pandas as pd
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy

logger = logging.getLogger(__name__)

class atr_tp(IStrategy):
    """EMA crossover strategy - Long when fast EMA crosses above slow EMA, Short when fast crosses below."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 50
    minimal_roi = {"0": 0.002}
    stoploss = -0.001
    trailing_stop = False
    use_custom_stoploss = False
    use_custom_exit = False
    
    # EMA parameters
    fast_ema_period = 10
    slow_ema_period = 30

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate EMA indicators and crossover signals."""
        # Calculate EMAs
        dataframe['fast_ema'] = ta.EMA(dataframe['close'], timeperiod=self.fast_ema_period)
        dataframe['slow_ema'] = ta.EMA(dataframe['close'], timeperiod=self.slow_ema_period)
        
        # Previous values for crossover detection
        dataframe['fast_ema_prev'] = dataframe['fast_ema'].shift(1)
        dataframe['slow_ema_prev'] = dataframe['slow_ema'].shift(1)
        
        # Detect crossovers
        # Long signal: fast EMA crosses above slow EMA
        dataframe['long_signal'] = (
            (dataframe['fast_ema'] > dataframe['slow_ema']) & 
            (dataframe['fast_ema_prev'] <= dataframe['slow_ema_prev'])
        )
        
        # Short signal: fast EMA crosses below slow EMA
        dataframe['short_signal'] = (
            (dataframe['fast_ema'] < dataframe['slow_ema']) & 
            (dataframe['fast_ema_prev'] >= dataframe['slow_ema_prev'])
        )
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Entry signals based on EMA crossovers."""
        dataframe.loc[dataframe['long_signal'], 'enter_long'] = 1
        dataframe.loc[dataframe['short_signal'], 'enter_short'] = 1
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Exit signals - relies on ROI and stoploss."""
        return dataframe

    def leverage(self, pair: str, current_time: datetime, current_rate: float, proposed_leverage: float, max_leverage: float, entry_tag: str | None, side: str, **kwargs) -> float:
        """Use 1x leverage."""
        return 1