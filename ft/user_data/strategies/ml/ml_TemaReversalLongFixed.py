# pragma pylint: disable=missing-docstring, invalid-name, pointless-string-statement
# flake8: noqa: F401
# isort: skip_file

from datetime import datetime

import numpy as np
import pandas as pd
from pandas import DataFrame

from freqtrade.strategy import IStrategy, informative
import talib.abstract as ta


class TemaReversalLongFixed(IStrategy):
    """
    ML Labeling Strategy: TEMA Reversal (Long-Only) - Fixed TP/SL

    Triple Barrier Method for binary classification:
    - Upper barrier: TP hit (+0.15%) = Label 1 (Success)
    - Lower barrier: SL hit (-0.15%) = Label 0 (Failure)
    - Time barrier: 1 hour timeout = Label 0 (or discard)

    Fixed 0.15% TP/SL based on median ATR analysis.
    Parameters tuned for ~50:50 label balance.
    """

    INTERFACE_VERSION = 3
    timeframe = "5s"
    can_short: bool = False

    # Fixed TP/SL at 0.15% (1:1 R:R for ~50% win rate)
    minimal_roi = {"0": 0.0015}  # 0.15% take profit
    stoploss = -0.0015  # 0.15% stop loss
    
    # Time barrier: exit after 1 hour if neither TP/SL hit
    # 720 candles * 5s = 3600s = 1 hour
    minimal_roi_time = {"720": 0}  # Exit at breakeven after 720 candles
    
    trailing_stop = False
    startup_candle_count: int = 200

    tema_length = 50
    atr_length = 20
    atr_multiplier = 1.5
    tp_risk_ratio = 1.0

    def informative_pairs(self):
        return []

    @informative("1m")
    def populate_indicators_1m(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe["atr"] = ta.ATR(
            dataframe["high"], dataframe["low"], dataframe["close"],
            timeperiod=self.atr_length
        )
        return dataframe

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # TEMA
        ema1 = ta.EMA(dataframe["close"], timeperiod=self.tema_length)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_length)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_length)
        dataframe["tema"] = 3 * ema1 - 3 * ema2 + ema3

        # Trend detection
        dataframe["tema_prev"] = dataframe["tema"].shift(1)
        dataframe["trend_up"] = dataframe["tema"] > dataframe["tema_prev"]
        dataframe["trend_down"] = dataframe["tema"] < dataframe["tema_prev"]
        dataframe["trend"] = np.where(
            dataframe["trend_up"],
            "UP",
            np.where(dataframe["trend_down"], "DOWN", "FLAT"),
        )

        # Trend flip detection
        dataframe["trend_prev"] = dataframe["trend"].shift(1)
        dataframe["trend_flip"] = (dataframe["trend"] != dataframe["trend_prev"]) & (
            dataframe["trend"] != "FLAT"
        )

        # ATR from 1m timeframe (for reference/features only)
        dataframe["atr"] = dataframe["atr_1m"]

        # Risk and TP/SL levels (for ML features, actual exits use fixed %)
        dataframe["risk"] = dataframe["atr"] * self.atr_multiplier
        dataframe["tp_long"] = dataframe["close"] * 1.0015  # Fixed +0.15%
        dataframe["sl_long"] = dataframe["close"] * 0.9985  # Fixed -0.15%

        # Reversal signal (long entry on trend flip to UP)
        dataframe["reversal_to_up"] = dataframe["trend_flip"] & (dataframe["trend"] == "UP")

        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        dataframe.loc[
            dataframe["reversal_to_up"]
            & dataframe["atr"].notna()
            & (dataframe["atr"] > 0)
            & dataframe["tema"].notna(),
            "enter_long",
        ] = 1

        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        return dataframe
