from datetime import datetime
from pandas import DataFrame
import numpy as np
import pandas as pd
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy

logger = logging.getLogger(__name__)

class TemaReversalBasic(IStrategy):
    """Trend-following strategy using TEMA reversal signals."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 150
    minimal_roi = {"0": 0.002}
    stoploss = -0.001
    trailing_stop = False
    use_custom_stoploss = False
    use_custom_exit = False
    tema_length = 50

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate indicators."""
        dataframe['tema'] = ta.TEMA(dataframe['close'], timeperiod=self.tema_length)
        dataframe['tema_prev'] = dataframe['tema'].shift(1)
        dataframe['trend_up'] = dataframe['tema'] > dataframe['tema_prev']
        dataframe['trend_down'] = dataframe['tema'] < dataframe['tema_prev']
        dataframe['trend'] = np.where(dataframe['trend_up'], 'UP', np.where(dataframe['trend_down'], 'DOWN', 'FLAT'))
        dataframe['trend_prev'] = dataframe['trend'].shift(1)
        dataframe['trend_flip'] = (dataframe['trend'] != dataframe['trend_prev']) & (dataframe['trend'] != 'FLAT')
        dataframe['reversal_to_up'] = dataframe['trend_flip'] & (dataframe['trend'] == 'UP')
        dataframe['reversal_to_down'] = dataframe['trend_flip'] & (dataframe['trend'] == 'DOWN')
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Entry signals based on trend reversals."""
        dataframe.loc[(dataframe['trend_flip'] & (dataframe['trend'] == 'UP')), 'enter_long'] = 1
        dataframe.loc[(dataframe['trend_flip'] & (dataframe['trend'] == 'DOWN')), 'enter_short'] = 1
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Exit signals - relies on ROI and stoploss."""
        return dataframe

    def leverage(self, pair: str, current_time: datetime, current_rate: float, proposed_leverage: float, max_leverage: float, entry_tag: str | None, side: str, **kwargs) -> float:
        """Use 1x leverage."""
        return 1