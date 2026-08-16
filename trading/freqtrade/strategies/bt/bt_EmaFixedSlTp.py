from datetime import datetime
from pandas import DataFrame
import numpy as np
import pandas as pd
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy

logger = logging.getLogger(__name__)

class EmaFixedSlTp(IStrategy):
    """EMA crossover strategy with fixed 0.1% SL and 0.2% TP."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = False
    process_only_new_candles = True
    startup_candle_count: int = 50
    
    # Fixed stoploss at 0.1%
    stoploss = -0.001
    trailing_stop = False
    
    # Fixed take-profit at 0.2%
    minimal_roi = {
        "0": 0.002
    }
    
    # Fixed parameters
    # EMA parameters
    fast_ema_period = 10
    slow_ema_period = 30

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate EMA indicators."""
        
        # Calculate EMAs
        dataframe['fast_ema'] = ta.EMA(dataframe['close'], timeperiod=self.fast_ema_period)
        dataframe['slow_ema'] = ta.EMA(dataframe['close'], timeperiod=self.slow_ema_period)
        
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
        # dataframe.loc[
        #     (fast_ema < slow_ema) & 
        #     (fast_ema_prev >= slow_ema_prev) &
        #     (dataframe['volume'] > 0),
        #     'enter_short'
        # ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Exit signals - handled by minimal_roi."""
        return dataframe

    def leverage(self, pair: str, current_time: datetime, current_rate: float, 
                proposed_leverage: float, max_leverage: float, entry_tag: str | None, 
                side: str, **kwargs) -> float:
        """Use 1x leverage."""
        return 1