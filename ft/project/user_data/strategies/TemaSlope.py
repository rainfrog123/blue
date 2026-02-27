from datetime import datetime
from pandas import DataFrame
import talib.abstract as ta
from freqtrade.strategy import IStrategy


class TemaSlope(IStrategy):
    """TEMA slope change strategy with fixed 0.1% SL and 0.2% TP."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = False
    process_only_new_candles = True
    startup_candle_count: int = 100
    
    stoploss = -0.001
    trailing_stop = False
    minimal_roi = {"0": 0.001}
    
    tema_period = 50
    max_bars = 100

    def custom_exit(self, pair: str, trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs):
        if (current_time - trade.open_date_utc).total_seconds() >= self.max_bars * 5:
            return 'timeout'
        return None

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # Calculate TEMA: 3*EMA1 - 3*EMA2 + EMA3
        ema1 = ta.EMA(dataframe['close'], timeperiod=self.tema_period)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_period)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_period)
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        # TEMA slope: UP=1, DOWN=-1, STABLE=0
        dataframe['tema_slope'] = 0
        dataframe.loc[dataframe['tema'] > dataframe['tema'].shift(1), 'tema_slope'] = 1
        dataframe.loc[dataframe['tema'] < dataframe['tema'].shift(1), 'tema_slope'] = -1
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # Long: TEMA slope changes from DOWN/STABLE to UP
        dataframe.loc[
            (dataframe['tema_slope'] == 1) &
            (dataframe['tema_slope'].shift(1) <= 0) &
            (dataframe['volume'] > 0),
            'enter_long'
        ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        return dataframe

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                proposed_leverage: float, max_leverage: float, entry_tag: str | None,
                side: str, **kwargs) -> float:
        return 1

