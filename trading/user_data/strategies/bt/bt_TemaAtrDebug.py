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
import talib.abstract as ta

# --- Freqtrade Imports ---
from freqtrade.persistence import Trade
from freqtrade.strategy import (
    IStrategy,
    IntParameter,
    CategoricalParameter,
    DecimalParameter
)

# --- Custom Strategy Class ---
class TemaAtrDebug(IStrategy):
    """
    Strategy for labeling trend reversals in trading data for machine learning tasks.
    """
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    
    # We use custom stoploss and exit logic - these are just placeholders
    minimal_roi = {"0": 100}  # Very high ROI means we rely on custom_exit
    stoploss = -0.99  # This is a placeholder, real stoploss is calculated dynamically
    trailing_stop = False
    use_custom_stoploss = True
    startup_candle_count: int = 170

    # ATR period parameter
    atr_period = 14

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
        # Debug print to check incoming data
        pair = metadata['pair']
        if not dataframe.empty:
            newest_candle = dataframe['date'].iloc[-1]
            candle_count = len(dataframe)
            print(f"DEBUG - {pair} - populate_indicators received {candle_count} candles. Newest: {newest_candle}")
            print(f"DEBUG - {pair} - Last 3 candles timestamps: {dataframe['date'].tail(3).values}")
            print(f"DEBUG - {pair} - Last 3 candles OHLCV: \n{dataframe[['date', 'open', 'high', 'low', 'close', 'volume']].tail(3)}")
            
            # Print data from approximately 10 minutes ago (120 candles for 5s timeframe)
            current_time = pd.to_datetime(newest_candle)
            target_time = current_time - pd.Timedelta(minutes=10)
            
            # Find candles closest to 10 minutes ago
            historical_candles = dataframe[dataframe['date'] > target_time].head(5)
            if not historical_candles.empty:
                print(f"DEBUG - {pair} - Historical data from ~10 minutes ago (after {target_time}):")
                print(f"DEBUG - {pair} - Historical OHLCV data: \n{historical_candles[['date', 'open', 'high', 'low', 'close', 'volume']]}")
            else:
                print(f"DEBUG - {pair} - No historical data found from ~10 minutes ago")
                
        else:
            print(f"DEBUG - {pair} - populate_indicators received EMPTY dataframe")

        # Ensure we are getting 5s data if that's what this strategy part expects
        # If self.timeframe is '5s', this will just get the regular dataframe. 
        # If self.timeframe was a shim (e.g., '1m'), this would fetch the 5s data.
        df_5s = dataframe # Default to the passed dataframe
        if self.dp and hasattr(self.dp, 'get_analyzed_dataframe') and self.timeframe != '5s':
            # This block would be relevant if we used a shim timeframe
            # For now, assuming self.timeframe IS '5s' due to the patch intention
            pass # df_5s, _ = self.dp.get_analyzed_dataframe(metadata['pair'], '5s')

        # TEMA indicator for trend direction
        tema_period = 50  # Increased for 5s timeframe to maintain similar time window
        df_5s['tema'] = ta.TEMA(df_5s['close'], timeperiod=tema_period)
        df_5s['trend'] = np.where(df_5s['tema'] > df_5s['tema'].shift(1), 'UP', 'DOWN')
        df_5s['trend_duration'] = (df_5s['trend'] != df_5s['trend'].shift(1)).cumsum()
        df_5s['trend_count'] = df_5s.groupby('trend_duration').cumcount() + 1
        
        # ATR calculation for stop loss and take profit
        df_5s['atr'] = ta.ATR(df_5s['high'], df_5s['low'], df_5s['close'], 
                                   timeperiod=self.atr_period)
        
        return df_5s # Return the (potentially 5s) dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate the entry signals based on trend reversal logic.
        Signals for long and short entries based on trend direction changes.
        """
        # Debug print for entry signals
        if not dataframe.empty:
            # Check if we have any entry signals in the last 10 candles
            last_10 = dataframe.tail(10).copy()
            
            # Fixed boolean operations
            long_signals = (last_10['trend'] == 'UP') & (last_10['trend'].shift(1) == 'DOWN')
            short_signals = (last_10['trend'] == 'DOWN') & (last_10['trend'].shift(1) == 'UP')
            
            if long_signals.any() or short_signals.any():
                print(f"DEBUG - {metadata['pair']} - Entry signals detected in last 10 candles:")
                if long_signals.any():
                    print(f"DEBUG - Long entry at: {last_10.loc[long_signals, 'date'].values}")
                if short_signals.any():
                    print(f"DEBUG - Short entry at: {last_10.loc[short_signals, 'date'].values}")
        
        # Apply long entry conditions
        long_conditions = (dataframe['trend'] == 'UP') & (dataframe['trend'].shift(1) == 'DOWN')
        dataframe.loc[long_conditions, 'enter_long'] = 1

        # Short entry signals
        short_conditions = (dataframe['trend'] == 'DOWN') & (dataframe['trend'].shift(1) == 'UP')
        dataframe.loc[short_conditions, 'enter_short'] = 1

        return dataframe
    
    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate the exit signals for the strategy.
        This method is left empty as we use custom_stoploss and custom_exit for exits.
        """
        return dataframe
    
    def custom_stoploss(self, pair: str, trade: Trade, current_time: datetime,
                        current_rate: float, current_profit: float, **kwargs) -> float:
        """
        Custom stoploss logic.
        
        Returns the stoploss percentage as a positive value between 0.0 and 1.0.
        0.01 would be a 1% loss.
        """
        # Explicitly request 5s data from the dataprovider
        dataframe_5s, _ = self.dp.get_analyzed_dataframe(pair, '5s')
        
        # Debug print to check dataframe in custom_stoploss
        print(f"DEBUG - {pair} - custom_stoploss called at {current_time}")
        if dataframe_5s is not None and not dataframe_5s.empty:
            newest_candle = dataframe_5s['date'].iloc[-1]
            candle_count = len(dataframe_5s)
            time_diff = (pd.to_datetime(current_time) - pd.to_datetime(newest_candle)).total_seconds()
            print(f"DEBUG - {pair} - custom_stoploss has {candle_count} candles. Newest: {newest_candle}")
            print(f"DEBUG - {pair} - Data age: {time_diff:.1f} seconds")
            print(f"DEBUG - {pair} - Last candle: {dataframe_5s[['date', 'open', 'high', 'low', 'close', 'volume', 'atr']].iloc[-1].to_dict()}")
        else:
            print(f"DEBUG - {pair} - custom_stoploss received EMPTY dataframe")
        
        if dataframe_5s is not None and len(dataframe_5s) > 0:
            # Get current ATR value from the 5s dataframe
            current_atr = dataframe_5s['atr'].iloc[-1]
            
            # Calculate stoploss percentage based on entry price and ATR
            # 0.25 * ATR defines our risk (stoploss distance)
            atr_stoploss_distance = 0.25 * current_atr
            
            # Convert from absolute price distance to percentage
            stoploss_percent = atr_stoploss_distance / trade.open_rate
            
            return stoploss_percent
            
        # Default fallback (1% stoploss)
        return 0.01
    
    def custom_exit(self, pair: str, trade: Trade, current_time: datetime, current_rate: float,
                    current_profit: float, **kwargs):
        """
        Custom exit logic for take profit based on 0.5 * ATR (2:1 reward:risk ratio).
        
        Returns exit tag (string) if exit should occur, or None otherwise.
        """
        # Explicitly request 5s data from the dataprovider
        dataframe_5s, _ = self.dp.get_analyzed_dataframe(pair, '5s')
        
        # Debug print to check dataframe in custom_exit
        print(f"DEBUG - {pair} - custom_exit called at {current_time}")
        if dataframe_5s is not None and not dataframe_5s.empty:
            newest_candle = dataframe_5s['date'].iloc[-1]
            candle_count = len(dataframe_5s)
            time_diff = (pd.to_datetime(current_time) - pd.to_datetime(newest_candle)).total_seconds()
            print(f"DEBUG - {pair} - custom_exit has {candle_count} candles. Newest: {newest_candle}")
            print(f"DEBUG - {pair} - Data age: {time_diff:.1f} seconds")
            print(f"DEBUG - {pair} - Last candle: {dataframe_5s[['date', 'open', 'high', 'low', 'close', 'volume', 'atr']].iloc[-1].to_dict()}")
        else:
            print(f"DEBUG - {pair} - custom_exit received EMPTY dataframe")
        
        if dataframe_5s is not None and len(dataframe_5s) > 0:
            # Get current ATR value from the 5s dataframe
            current_atr = dataframe_5s['atr'].iloc[-1]
            
            # Calculate take profit distance (0.5 * ATR)
            atr_take_profit_distance = 0.5 * current_atr
            
            # Convert distance to percentage
            take_profit_percent = atr_take_profit_distance / trade.open_rate
            
            # Check if current profit exceeds our take profit level
            # This gives us 2:1 reward:risk (0.5 ATR vs 0.25 ATR)
            if current_profit >= take_profit_percent:
                print(f"DEBUG - {pair} - Taking profit at {current_profit:.4f}% (target: {take_profit_percent:.4f}%)")
                return 'take_profit_atr'
                
        return None

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, entry_tag: Optional[str],
                 side: str, **kwargs) -> float:
        """
        Return the leverage to use for a trade.
        """
        return max_leverage
        # return 100.0

    def custom_stake_amount(self, pair: str, current_time: datetime, current_rate: float,
                            proposed_stake: float, min_stake: float | None, max_stake: float,
                            leverage: float, entry_tag: str | None, side: str,
                            **kwargs) -> float:
        """
        Custom stake amount logic - uses 75% of the total available balance.
        """
        # Fetch the total balance in the stake currency
        # total_balance = self.wallets.get_total_balance(self.config['stake_currency'])
        total_balance = self.wallets.get_total_stake_amount()

        # Calculate 3/4 (75%) of the total balance
        stake_amount = total_balance * 0.75

        # Ensure the stake amount is within allowed limits
        return stake_amount
