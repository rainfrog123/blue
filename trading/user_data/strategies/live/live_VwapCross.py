from datetime import datetime
from pandas import DataFrame
import numpy as np
from freqtrade.strategy import IStrategy, IntParameter, DecimalParameter


class VwapCross(IStrategy):
    """VWAP crossover strategy - long when price crosses above VWAP."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = False
    process_only_new_candles = True
    startup_candle_count: int = 500
    
    stoploss = -0.003
    trailing_stop = False
    minimal_roi = {"0": 1}
    
    # Hyperopt parameters
    vwap_period = IntParameter(120, 720, default=360, space='buy')
    tp_pct = DecimalParameter(0.001, 0.005, default=0.002, decimals=4, space='sell')
    sl_pct = DecimalParameter(0.001, 0.003, default=0.001, decimals=4, space='sell')
    max_bars = IntParameter(60, 240, default=120, space='sell')

    def custom_exit(self, pair: str, trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs):
        # Take profit
        if current_profit >= self.tp_pct.value:
            return 'tp'
        # Stop loss
        if current_profit <= -self.sl_pct.value:
            return 'sl'
        # Timeout
        if (current_time - trade.open_date_utc).total_seconds() >= self.max_bars.value * 5:
            return 'timeout'
        return None

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # Rolling VWAP = cumsum(typical_price * volume) / cumsum(volume)
        typical_price = (dataframe['high'] + dataframe['low'] + dataframe['close']) / 3
        tp_vol = typical_price * dataframe['volume']
        
        # Calculate VWAP for all periods in hyperopt range
        for period in range(self.vwap_period.low, self.vwap_period.high + 1, 60):
            dataframe[f'vwap_{period}'] = (
                tp_vol.rolling(window=period).sum() / 
                dataframe['volume'].rolling(window=period).sum()
            )
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # Round vwap_period to nearest 60
        period = ((self.vwap_period.value + 30) // 60) * 60
        vwap_col = f'vwap_{period}'
        
        # Long: price crosses above VWAP (was below, now above)
        dataframe.loc[
            (dataframe['close'] > dataframe[vwap_col]) &
            (dataframe['close'].shift(1) <= dataframe[vwap_col].shift(1)) &
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
