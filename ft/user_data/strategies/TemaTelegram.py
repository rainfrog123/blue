# pragma pylint: disable=missing-docstring, invalid-name, pointless-string-statement
# flake8: noqa: F401
# isort: skip_file

from freqtrade.strategy import IStrategy
from pandas import DataFrame
import logging
from datetime import datetime, timedelta
import talib.abstract as ta
import pandas as pd

logger = logging.getLogger(__name__)

class TemaTelegram(IStrategy):
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    
    # Only process new candles, not all historical data
    process_only_new_candles = True
    
    # More realistic ROI: 1% profit target
    minimal_roi = {"0": 0.01, "10": 0.005, "30": 0}
    # Tighter stop loss for 5s timeframe
    stoploss = -0.01
    trailing_stop = False  # We'll use custom trailing stop
    use_custom_stoploss = True  # Enable ATR-based trailing stop
    startup_candle_count: int = 60  # Need more candles for TEMA calculation (50 + buffer)

    # Manual confirmation system
    pending_confirmations = {}  # Track when we last sent notifications
    confirmation_cooldown = timedelta(minutes=1)  # Prevent spam - 1 minute between notifications

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # TEMA calculation (Triple Exponential Moving Average)
        tema_period = 50
        
        # Calculate the three EMAs for TEMA
        ema1 = ta.EMA(dataframe['close'], timeperiod=tema_period)
        ema2 = ta.EMA(ema1, timeperiod=tema_period)
        ema3 = ta.EMA(ema2, timeperiod=tema_period)
        
        # TEMA formula: 3 * EMA1 - 3 * EMA2 + EMA3
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        # Calculate trend direction
        dataframe['tema_prev'] = dataframe['tema'].shift(1)
        dataframe['trend_up'] = dataframe['tema'] > dataframe['tema_prev']
        dataframe['trend_down'] = dataframe['tema'] < dataframe['tema_prev']
        dataframe['trend_stable'] = (dataframe['tema'] == dataframe['tema_prev'])
        
        # Track trend changes
        dataframe['prev_trend_up'] = dataframe['trend_up'].shift(1)
        dataframe['prev_trend_down'] = dataframe['trend_down'].shift(1)
        
        # Detect trend reversals
        dataframe['reversal_to_up'] = (~dataframe['prev_trend_up']) & dataframe['trend_up']
        dataframe['reversal_to_down'] = (~dataframe['prev_trend_down']) & dataframe['trend_down']
        
        # ATR for trailing stop calculation
        dataframe['atr'] = ta.ATR(dataframe, timeperiod=14)
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # Get pair name for logging
        pair = metadata['pair']
        
        # MANUAL CONFIRMATION SYSTEM - No automatic entries
        dataframe['enter_long'] = 0
        dataframe['enter_short'] = 0
        
        # Check for TEMA reversal signals on the latest candle only
        if not dataframe.empty and len(dataframe) > 1:
            current_time = datetime.now()
            last_notification = self.pending_confirmations.get(pair)
            
            # Check for reversal signals
            long_signal = dataframe['reversal_to_up'].iloc[-1] if not dataframe['reversal_to_up'].isna().iloc[-1] else False
            short_signal = dataframe['reversal_to_down'].iloc[-1] if not dataframe['reversal_to_down'].isna().iloc[-1] else False
            
            if (long_signal or short_signal) and (last_notification is None or (current_time - last_notification > self.confirmation_cooldown)):
                # Get signal details
                current_price = dataframe['close'].iloc[-1]
                current_tema = dataframe['tema'].iloc[-1] if not dataframe['tema'].isna().iloc[-1] else 0
                prev_tema = dataframe['tema_prev'].iloc[-1] if not dataframe['tema_prev'].isna().iloc[-1] else 0
                tema_change = current_tema - prev_tema if prev_tema != 0 else 0
                
                # Determine signal type
                signal_type = "LONG" if long_signal else "SHORT"
                signal_emoji = "🟢" if long_signal else "🔴"
                trend_direction = "UP" if long_signal else "DOWN"
                command = f"/forcelong {pair}" if long_signal else f"/forceshort {pair}"
                
                # Create confirmation message
                message = (
                    f"{signal_emoji} TEMA REVERSAL SIGNAL {signal_emoji}\n"
                    f"📊 Pair: {pair}\n"
                    f"💰 Price: ${current_price:.4f}\n"
                    f"📈 TEMA: {current_tema:.4f}\n"
                    f"🔄 Change: {tema_change:.4f}\n"
                    f"📊 Trend: {trend_direction}\n"
                    f"🎯 Signal: {signal_type}\n"
                    f"⏰ Time: {current_time.strftime('%H:%M:%S')}\n\n"
                    f"💡 To enter trade, copy and send:\n"
                    f"`{command}`"
                )
                
                # Send Telegram notification
                if self.dp and hasattr(self.dp, 'send_msg'):
                    try:
                        self.dp.send_msg(message)
                        self.pending_confirmations[pair] = current_time
                        logger.info(f"🎯 Sent TEMA {signal_type} confirmation request for {pair} (TEMA: {current_tema:.4f}, Change: {tema_change:.4f})")
                    except Exception as e:
                        logger.error(f"Failed to send Telegram message: {e}")
                else:
                    logger.warning("DataProvider send_msg not available - check Telegram config")
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        # No exit signals - using only ATR-based trailing stop
        dataframe['exit_long'] = 0
        dataframe['exit_short'] = 0
        return dataframe

    def custom_stoploss(self, pair: str, trade: 'Trade', current_time: datetime,
                       current_rate: float, current_profit: float, **kwargs) -> float:
        """
        Custom ATR-based trailing stoploss.
        Uses ATR * 0.5 as the trailing stop distance.
        """
        # Get the latest analyzed dataframe
        dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
        
        if dataframe is None or dataframe.empty:
            # Fallback to initial stoploss if no data
            return self.stoploss
        
        # Get the latest ATR value
        latest_atr = dataframe['atr'].iloc[-1]
        
        if pd.isna(latest_atr) or latest_atr <= 0:
            # Fallback to initial stoploss if ATR is invalid
            return self.stoploss
        
        # Calculate ATR-based stop distance (ATR * 0.5)
        atr_stop_distance = latest_atr * 0.5
        
        # Convert to percentage of current rate
        stop_percentage = atr_stop_distance / current_rate
        
        # For long positions, return negative percentage (stop below current price)
        # For short positions, return positive percentage (stop above current price)
        if trade.is_short:
            return stop_percentage
        else:
            return -stop_percentage

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, entry_tag: str | None, side: str,
                 **kwargs) -> float:
        """
        Customize leverage for each new trade. This method is only called in futures mode.
        """
        return max_leverage
