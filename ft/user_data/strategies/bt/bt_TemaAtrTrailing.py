# pragma pylint: disable=missing-docstring, invalid-name, pointless-string-statement
# flake8: noqa: F401
# isort: skip_file

# --- Standard Library Imports ---
from datetime import datetime
from typing import Optional, Union

# --- Third Party Imports ---
import numpy as np
import pandas as pd
from pandas import DataFrame
import random

# --- Freqtrade Imports ---
from freqtrade.strategy import (
    IStrategy,
    IntParameter,
    DecimalParameter
)

# --- Technical Analysis Library Imports ---
import talib.abstract as ta

# --- Custom Strategy Class ---
class TemaAtrTrailing(IStrategy):
    """
    Strategy for labeling trend reversals in trading data for machine learning tasks.
    """
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    
    # Dynamic ROI to allow trailing stop to handle exits
    minimal_roi = {"0": 100.0}  # Essentially disable normal ROI
    
    # Base stoploss - will be dynamically adjusted based on ATR
    stoploss = -0.001  # Initial value, will be multiplied by leverage
    
    # Enable trailing stop
    trailing_stop = True
    
    # Only trail after reaching profit threshold (set to 0 to always trail)
    trailing_only_offset_is_reached = False
    trailing_stop_positive_offset = 0.0
    
    # Settings for ATR-based trailing stop
    # ATR multiplier for trailing stop distance (higher = more room for price movement)
    atr_multiplier = DecimalParameter(1.0, 3.0, default=1.5, space="buy", optimize=True)
    
    # ATR period - how many candles to look back
    atr_period = IntParameter(10, 100, default=20, space="buy", optimize=True)
    
    # Minimum trailing stop distance as percentage of price (to prevent too tight stops)
    min_trailing_stop = DecimalParameter(0.0001, 0.0010, default=0.0005, space="buy", optimize=True)
    
    # Startup candles needed to calculate indicators
    startup_candle_count: int = 100  # Increased to allow for ATR calculation
    
    # Use dynamic trailing_stop_positive based on ATR
    use_custom_stoploss = True

    def informative_pairs(self):
        """
        Define pairs for additional, informative data.
        Currently returns an empty list.
        """
        return []

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Add all necessary technical indicators to the DataFrame.
        Currently includes Triple Exponential Moving Average (TEMA) and ATR.
        """
        # TEMA calculation for trend identification
        tema_period = 50  # Increased for 5s timeframe to maintain similar time window
        dataframe['tema'] = ta.TEMA(dataframe['close'], timeperiod=tema_period)
        dataframe['trend'] = np.where(dataframe['tema'] > dataframe['tema'].shift(1), 'UP', 'DOWN')
        dataframe['trend_duration'] = (dataframe['trend'] != dataframe['trend'].shift(1)).cumsum()
        dataframe['trend_count'] = dataframe.groupby('trend_duration').cumcount() + 1
        
        # Calculate ATR for dynamic stop loss
        for val in self.atr_period.range:
            dataframe[f'atr_{val}'] = ta.ATR(dataframe['high'], dataframe['low'], dataframe['close'], timeperiod=val)
        
        # Current ATR value based on parameter
        dataframe['atr'] = dataframe[f'atr_{self.atr_period.value}']
        
        # ATR percentage of price (ATR/close_price)
        dataframe['atr_pct'] = dataframe['atr'] / dataframe['close']
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate the entry signals based on trend reversal logic.
        Signals for long and short entries based on trend direction changes.
        """
        # Apply long entry conditions based only on trend change
        long_conditions = (dataframe['trend'] == 'UP') & (dataframe['trend'].shift(1) == 'DOWN')
        dataframe.loc[long_conditions, 'enter_long'] = 1

        # Apply short entry conditions based only on trend change
        short_conditions = (dataframe['trend'] == 'DOWN') & (dataframe['trend'].shift(1) == 'UP')
        dataframe.loc[short_conditions, 'enter_short'] = 1

        return dataframe
    
    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate the exit signals for the strategy.
        This method is left empty for further customization.
        """
        return dataframe
    
    def custom_stoploss(self, pair: str, trade: 'Trade', current_time: datetime,
                       current_rate: float, current_profit: float, **kwargs) -> float:
        """
        Custom stoploss logic, returning the new distance relative to current_rate.
        Returning None values means to use the initial fixed stoploss value.
        
        For docstring examples, see: 
        https://www.freqtrade.io/en/stable/strategy-advanced/
        """
        # Get dataframe
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        
        # Get the latest candle
        last_candle = dataframe.iloc[-1].squeeze()
        
        # Calculate ATR-based stoploss distance (adjusted for leverage)
        atr_distance = last_candle['atr'] * self.atr_multiplier.value
        atr_stoploss_pct = atr_distance / current_rate
        
        # Apply minimum stoploss distance if needed (prevent too tight stops)
        stoploss_distance = max(atr_stoploss_pct, self.min_trailing_stop.value)
        
        # For shorts, we need a positive stoploss distance 
        # For longs, we need a negative stoploss distance
        if trade.is_short:
            return stoploss_distance
        else:
            return -stoploss_distance

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, entry_tag: Optional[str],
                 side: str, **kwargs) -> float:
        return max_leverage
        # return 100.0

    def custom_stake_amount(self, pair: str, current_time: datetime, current_rate: float,
                            proposed_stake: float, min_stake: float | None, max_stake: float,
                            leverage: float, entry_tag: str | None, side: str,
                            **kwargs) -> float:

        # Fetch the total balance in the stake currency
        # total_balance = self.wallets.get_total_balance(self.config['stake_currency'])
        total_balance = self.wallets.get_total_stake_amount()

        # Calculate 3/4 (75%) of the total balance
        stake_amount = total_balance * 0.75
        
        # Ensure the stake amount is within allowed limits
        return stake_amount
