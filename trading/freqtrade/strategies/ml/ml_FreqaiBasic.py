import logging
from functools import reduce
import talib.abstract as ta
from pandas import DataFrame
from technical import qtpylib
from freqtrade.strategy import IStrategy
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

class FreqaiBasic(IStrategy):
    """
    A strategy utilizing AI-based classification for dynamic long and short entry/exit decisions.
    """
    
    # Strategy-specific configurations
    minimal_roi = {"0": 1000000.0}
    stoploss = -0.05
    trailing_stop = True
    process_only_new_candles = False
    startup_candle_count: int = 100  # Increased for 5s timeframe
    can_short = True
    timeframe = '5s'
    # Plot configuration
    plot_config = {
        "main_plot": {}
    }

    def feature_engineering_expand_all(self, dataframe: DataFrame, period: int, metadata: dict, **kwargs) -> DataFrame:
        """
        Comprehensive feature engineering with extensive technical indicators
        """
        # Momentum Indicators
        dataframe["%-rsi-period"] = ta.RSI(dataframe, timeperiod=period)
        dataframe["%-mfi-period"] = ta.MFI(dataframe, timeperiod=period)
        dataframe["%-adx-period"] = ta.ADX(dataframe, timeperiod=period)
        dataframe["%-plus_di-period"] = ta.PLUS_DI(dataframe, timeperiod=period)
        dataframe["%-minus_di-period"] = ta.MINUS_DI(dataframe, timeperiod=period)
        dataframe["%-cci-period"] = ta.CCI(dataframe, timeperiod=period)
        dataframe["%-cmo-period"] = ta.CMO(dataframe, timeperiod=period)
        dataframe["%-mom-period"] = ta.MOM(dataframe, timeperiod=period)
        dataframe["%-roc-period"] = ta.ROC(dataframe, timeperiod=period)
        dataframe["%-trix-period"] = ta.TRIX(dataframe, timeperiod=period)
        dataframe["%-willr-period"] = ta.WILLR(dataframe, timeperiod=period)
        
        # Volume Indicators
        dataframe["%-obv-period"] = ta.OBV(dataframe)
        dataframe["%-ad-period"] = ta.AD(dataframe)
        dataframe["%-adosc-period"] = ta.ADOSC(dataframe)
        dataframe["%-relative_volume-period"] = dataframe["volume"] / dataframe["volume"].rolling(period).mean()
        
        # Volatility Indicators
        dataframe["%-atr-period"] = ta.ATR(dataframe, timeperiod=period)
        dataframe["%-natr-period"] = ta.NATR(dataframe, timeperiod=period)
        dataframe["%-trange-period"] = ta.TRANGE(dataframe)
        dataframe["%-dx-period"] = ta.DX(dataframe, timeperiod=period)
        # Moving Averages
        dataframe["%-sma-period"] = ta.SMA(dataframe, timeperiod=period)
        dataframe["%-ema-period"] = ta.EMA(dataframe, timeperiod=period)
        dataframe["%-tema-period"] = ta.TEMA(dataframe, timeperiod=period)
        dataframe["%-dema-period"] = ta.DEMA(dataframe, timeperiod=period)
        dataframe["%-kama-period"] = ta.KAMA(dataframe, timeperiod=period)
        dataframe["%-trima-period"] = ta.TRIMA(dataframe, timeperiod=period)
        dataframe["%-wma-period"] = ta.WMA(dataframe, timeperiod=period)
        dataframe["%-t3-period"] = ta.T3(dataframe, timeperiod=period)
        
        # Stochastic Indicators with period parameter
        stoch = ta.STOCH(dataframe, fastk_period=period, slowk_period=period, slowd_period=period)
        dataframe["%-stoch_k-period"] = stoch.slowk
        dataframe["%-stoch_d-period"] = stoch.slowd
        
        stochf = ta.STOCHF(dataframe, fastk_period=period, fastd_period=period)
        dataframe["%-stochf_k-period"] = stochf.fastk
        dataframe["%-stochf_d-period"] = stochf.fastd
        
        # Bollinger Bands
        bollinger = qtpylib.bollinger_bands(qtpylib.typical_price(dataframe), window=period, stds=2.2)
        dataframe["%-bb_lower-period"] = bollinger["lower"]
        dataframe["%-bb_middle-period"] = bollinger["mid"]
        dataframe["%-bb_upper-period"] = bollinger["upper"]
        dataframe["%-bb_width-period"] = (bollinger["upper"] - bollinger["lower"]) / bollinger["mid"]
        
        # Price Action Features
        dataframe["%-high_low_range-period"] = (dataframe['high'] - dataframe['low'])
        dataframe["%-body_size-period"] = abs(dataframe['open'] - dataframe['close'])
        dataframe["%-upper_shadow-period"] = dataframe['high'] - dataframe[['open', 'close']].max(axis=1)
        dataframe["%-lower_shadow-period"] = dataframe[['open', 'close']].min(axis=1) - dataframe['low']
        
        # Price Ratios and Averages
        dataframe["%-close_to_high-period"] = dataframe['close'] / dataframe['high']
        dataframe["%-close_to_low-period"] = dataframe['close'] / dataframe['low']
        dataframe["%-hlc3-period"] = (dataframe['high'] + dataframe['low'] + dataframe['close']) / 3
        dataframe["%-ohlc4-period"] = (dataframe['open'] + dataframe['high'] + dataframe['low'] + dataframe['close']) / 4
        
        # Percentage Changes
        dataframe["%-close_change-period"] = dataframe['close'].pct_change(period)
        dataframe["%-volume_change-period"] = dataframe['volume'].pct_change(period)
        dataframe["%-high_change-period"] = dataframe['high'].pct_change(period)
        dataframe["%-low_change-period"] = dataframe['low'].pct_change(period)
        
        # Volatility Features
        dataframe["%-volatility-period"] = dataframe['close'].rolling(window=period).std()
        dataframe["%-range_ma-period"] = dataframe["%-high_low_range-period"].rolling(window=period).mean()
        
        return dataframe

    def feature_engineering_expand_basic(self, dataframe: DataFrame, metadata: dict, **kwargs) -> DataFrame:
        """
        *Only functional with FreqAI enabled strategies*
        This function will automatically expand the defined features on the config defined
        `include_timeframes`, `include_shifted_candles`, and `include_corr_pairs`.
        """
        dataframe["%-pct-change"] = dataframe["close"].pct_change()
        dataframe["%-raw_volume"] = dataframe["volume"]
        dataframe["%-raw_price"] = dataframe["close"]
        return dataframe

    def feature_engineering_standard(self, dataframe: DataFrame, metadata: dict, **kwargs) -> DataFrame:
        """
        Add standard features with some additional time-based features
        """
        # Existing time-based features
        dataframe["%-day_of_week"] = (dataframe["date"].dt.dayofweek + 1) / 7
        dataframe["%-hour_of_day"] = (dataframe["date"].dt.hour + 1) / 25
        
        # Add new time-based features
        dataframe["%-minute_of_hour"] = (dataframe["date"].dt.minute + 1) / 60
        dataframe["%-is_weekend"] = dataframe["date"].dt.weekday.isin([5, 6]).astype(float)
        
        # Trading session indicators (normalized to 0-1)
        hour = dataframe["date"].dt.hour
        dataframe["%-asian_session"] = ((hour >= 1) & (hour < 9)).astype(float)
        dataframe["%-london_session"] = ((hour >= 8) & (hour < 16)).astype(float)
        dataframe["%-ny_session"] = ((hour >= 13) & (hour < 21)).astype(float)
        
        return dataframe

    def set_freqai_targets(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Map external targets from a parquet file to the main dataframe.
        """
        self.freqai.class_names = ['WIN', 'LOSE']
        
        # Load external parquet file
        external_df = pd.read_parquet('/allah/data/parquet/filtered_df.parquet')

        # Ensure `open_date` is a datetime object
        external_df['open_date'] = pd.to_datetime(external_df['open_date'])
        
        # Create `target_date` as 10 seconds before `open_date` (adjusted for 5s timeframe)
        external_df['target_date'] = external_df['open_date'] - pd.Timedelta(seconds=10)
        
        # Filter for only LONG_WIN and SHORT_WIN
        # external_df = external_df[external_df['type'].isin(['LONG_WIN', 'SHORT_WIN'])]

        # Map targets to the main dataframe
        target_map = external_df.set_index('target_date')['profitability'].to_dict()
        dataframe['profitability'] = dataframe['date'].map(target_map)
        dataframe['&-target'] = dataframe['profitability']
        
        return dataframe

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate indicators for the AI-based prediction.
        """
        dataframe = self.freqai.start(dataframe, metadata, self)
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Define entry conditions for long and short positions based on AI predictions.
        """
 
        # Long entry conditions (when prediction is 'LONG_WIN')
        enter_long_conditions = [
            dataframe["do_predict"] == 1,  # Prediction confidence is high
            dataframe["&-target"] == 'LONG_WIN',  # Predicted to win in a long position
        ]
        if enter_long_conditions:
            dataframe.loc[
                reduce(lambda x, y: x & y, enter_long_conditions), ["enter_long", "enter_tag"]
            ] = (1, "long")

        # Short entry conditions (when prediction is 'SHORT_WIN')
        enter_short_conditions = [
            dataframe["do_predict"] == 1,  # Prediction confidence is high
            dataframe["&-target"] == 'SHORT_WIN',  # Predicted to win in a short position
        ]
        if enter_short_conditions:
            dataframe.loc[
                reduce(lambda x, y: x & y, enter_short_conditions), ["enter_short", "enter_tag"]
            ] = (1, "short")

        return dataframe


    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Define exit conditions for long and short positions based on AI predictions.
        """
        # Exit long if prediction changes to "down"

        return dataframe