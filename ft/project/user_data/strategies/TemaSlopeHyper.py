from datetime import datetime
from pandas import DataFrame
import talib.abstract as ta
from freqtrade.strategy import IStrategy, DecimalParameter


class TemaSlopeHyper(IStrategy):
    """TEMA slope strategy with ATR-based SL/TP hyperopt."""
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short = False
    process_only_new_candles = True
    startup_candle_count = 100
    use_custom_stoploss = True
    
    stoploss = -0.1  # fallback
    trailing_stop = False
    
    tema_period = 50
    atr_period = 14
    
    # Hyperopt params
    sl_atr = DecimalParameter(0.5, 5.0, default=1.0, space='sell', optimize=True)
    tp_atr = DecimalParameter(0.5, 5.0, default=2.0, space='sell', optimize=True)

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        ema1 = ta.EMA(dataframe['close'], timeperiod=self.tema_period)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_period)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_period)
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        dataframe['tema_slope'] = 0
        dataframe.loc[dataframe['tema'] > dataframe['tema'].shift(1), 'tema_slope'] = 1
        dataframe.loc[dataframe['tema'] < dataframe['tema'].shift(1), 'tema_slope'] = -1
        
        dataframe['atr'] = ta.ATR(dataframe, timeperiod=self.atr_period)
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe.loc[
            (dataframe['tema_slope'] == 1) &
            (dataframe['tema_slope'].shift(1) <= 0) &
            (dataframe['volume'] > 0),
            'enter_long'
        ] = 1
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        return dataframe

    def custom_stoploss(self, pair: str, trade, current_time: datetime,
                        current_rate: float, current_profit: float, **kwargs) -> float:
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        if dataframe.empty:
            return self.stoploss
        
        last = dataframe.iloc[-1]
        atr = last['atr']
        if atr <= 0:
            return self.stoploss
        
        sl_dist = atr * self.sl_atr.value
        sl_pct = sl_dist / trade.open_rate
        return -sl_pct

    def custom_exit(self, pair: str, trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs):
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        if dataframe.empty:
            return None
        
        last = dataframe.iloc[-1]
        atr = last['atr']
        if atr <= 0:
            return None
        
        tp_dist = atr * self.tp_atr.value
        tp_pct = tp_dist / trade.open_rate
        
        if current_profit >= tp_pct:
            return 'tp_atr'
        return None

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                proposed_leverage: float, max_leverage: float, entry_tag: str | None,
                side: str, **kwargs) -> float:
        return 1

