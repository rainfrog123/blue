from datetime import datetime
from pandas import DataFrame
import numpy as np
import pandas as pd
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy, informative
from freqtrade.persistence import Trade, Order

logger = logging.getLogger(__name__)

class TemaRandom(IStrategy):
    """Trend-following strategy using TEMA with random entry filtering."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 150
    minimal_roi = {"0": 1}
    stoploss = -0.001 * 125
    trailing_stop = False
    use_custom_stoploss = False
    use_custom_exit = True
    tema_length = 50
    atr_length = 14

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate indicators. 1m data merged via @informative."""
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
        """Entry signals based on trend reversals with 1m filter."""
        np.random.seed(42)
        dataframe['random_entry'] = np.random.random(len(dataframe)) < 1
        tema_1m_filter_long = dataframe.get('tema_trend_1m', 0) > 0 if 'tema_trend_1m' in dataframe.columns else True
        tema_1m_filter_short = dataframe.get('tema_trend_1m', 0) < 0 if 'tema_trend_1m' in dataframe.columns else True
        
        dataframe.loc[(dataframe['trend_flip'] & (dataframe['trend'] == 'UP') & dataframe['random_entry'] & tema_1m_filter_long), 'enter_long'] = 1
        dataframe.loc[(dataframe['trend_flip'] & (dataframe['trend'] == 'DOWN') & dataframe['random_entry'] & tema_1m_filter_short), 'enter_short'] = 1
        return dataframe

    @informative('1m')
    def populate_indicators_1m(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe['tema'] = ta.TEMA(dataframe['close'], timeperiod=self.tema_length)
        dataframe['tema_prev'] = dataframe['tema'].shift(1)
        dataframe['tema_trend'] = np.where(dataframe['tema'] > dataframe['tema_prev'], 1, -1)
        return dataframe

    def custom_exit(self, pair: str, trade: Trade, current_time: datetime, current_rate: float, current_profit: float, **kwargs):
        if trade.has_open_orders:
            return None
        if trade.nr_of_successful_exits == 0 and trade.get_custom_data("tp_placed") != True:
            trade.set_custom_data(key="tp_placed", value=True)
            return "place_tp_now"
        return None

    def custom_exit_price(self, pair: str, trade: Trade, current_time: datetime, proposed_rate: float, current_profit: float, exit_tag: str | None, **kwargs) -> float:
        """Set custom exit price - 0.2% profit target."""
        risk_factor = 0.002
        target = trade.open_rate * (1 - risk_factor) if trade.is_short else trade.open_rate * (1 + risk_factor)
        return target

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Exit signals - relies on ROI and stoploss."""
        return dataframe

    def leverage(self, pair: str, current_time: datetime, current_rate: float, proposed_leverage: float, max_leverage: float, entry_tag: str | None, side: str, **kwargs) -> float:
        """Use maximum available leverage."""
        return max_leverage