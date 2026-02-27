# pragma pylint: disable=missing-docstring, invalid-name, pointless-string-statement
# flake8: noqa: F401
# isort: skip_file

from freqtrade.strategy import IStrategy, informative
from pandas import DataFrame
import logging
from datetime import datetime
import talib.abstract as ta
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

class TemaReversal2R(IStrategy):
    """
    TEMA Reversal Strategy
    
    Based on Pine Script: "TEMA Reversal TP/SL (2 R ATR Clean)"
    
    This strategy enters trades on TEMA trend reversals with 2R:1R TP/SL levels.
    
    Key Features:
    - TEMA-based trend detection
    - ATR from higher timeframe (1m) for risk calculation
    - Automatic 2R:1R TP/SL on trend flips
    - Clean entry/exit signals
    """
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    
    # Process only new candles for live trading efficiency
    process_only_new_candles = True
    
    # ROI and stoploss (overridden by custom logic)
    minimal_roi = {"0": 0.06, "10": 0.03, "30": 0}
    stoploss = -0.03
    trailing_stop = False
    use_custom_stoploss = True
    startup_candle_count: int = 60

    # Strategy parameters (matching Pine Script exactly)
    tema_length = 50         # TEMA Length
    atr_length = 14          # ATR Length  
    atr_multiplier = 3.0     # ATR Multiplier (1R risk)
    tp_risk_ratio = 2.0      # TP = 2R (2:1 reward:risk ratio)

    def informative_pairs(self):
        """
        Define informative pairs for higher timeframe ATR
        """
        return []

    @informative('1m')
    def populate_indicators_1m(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Calculate ATR on 1m timeframe for more stable risk management
        """
        # Calculate ATR on 1m timeframe
        dataframe['atr'] = ta.ATR(dataframe, timeperiod=self.atr_length)
        
        return dataframe

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Populate indicators matching Pine Script "TEMA Reversal TP/SL (2 R ATR Clean)"
        """
        # === TEMA CALCULATION ===
        # Triple Exponential Moving Average (exactly as Pine Script)
        ema1 = ta.EMA(dataframe['close'], timeperiod=self.tema_length)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_length)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_length)
        
        # TEMA formula: 3 * ema1 - 3 * ema2 + ema3
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        # === TREND DETECTION ===
        # Trend direction (matching Pine Script logic)
        dataframe['tema_prev'] = dataframe['tema'].shift(1)
        dataframe['trend_up'] = dataframe['tema'] > dataframe['tema_prev']
        dataframe['trend_down'] = dataframe['tema'] < dataframe['tema_prev']
        
        # Trend classification
        dataframe['trend'] = np.where(
            dataframe['trend_up'], 'UP',
            np.where(dataframe['trend_down'], 'DOWN', 'FLAT')
        )
        
        # === TREND FLIP DETECTION ===
        # Detect when trend changes from previous bar
        dataframe['trend_prev'] = dataframe['trend'].shift(1)
        dataframe['trend_flip'] = (dataframe['trend'] != dataframe['trend_prev']) & (dataframe['trend'] != 'FLAT')
        
        # === ATR FROM HIGHER TIMEFRAME ===
        # The @informative decorator automatically provides atr_1m column
        # No manual merging needed - it's handled automatically by freqtrade
        
        # Use the ATR from 1m timeframe (automatically merged as 'atr_1m')
        dataframe['atr'] = dataframe['atr_1m']
        
        # === ENTRY AND RISK LEVELS ===
        # Entry price (current close)
        dataframe['entry_price'] = dataframe['close']
        
        # Risk calculation (1R = ATR * multiplier)
        dataframe['risk'] = dataframe['atr'] * self.atr_multiplier
        
        # === TP/SL LEVELS (2R:1R) ===
        # Long positions: TP above entry, SL below entry
        dataframe['tp_long'] = np.where(
            dataframe['trend'] == 'UP',
            dataframe['entry_price'] + (self.tp_risk_ratio * dataframe['risk']),
            np.nan
        )
        dataframe['sl_long'] = np.where(
            dataframe['trend'] == 'UP',
            dataframe['entry_price'] - dataframe['risk'],
            np.nan
        )
        
        # Short positions: TP below entry, SL above entry
        dataframe['tp_short'] = np.where(
            dataframe['trend'] == 'DOWN',
            dataframe['entry_price'] - (self.tp_risk_ratio * dataframe['risk']),
            np.nan
        )
        dataframe['sl_short'] = np.where(
            dataframe['trend'] == 'DOWN',
            dataframe['entry_price'] + dataframe['risk'],
            np.nan
        )
        
        # === REVERSAL SIGNALS ===
        # Entry signals on trend flips
        dataframe['reversal_to_up'] = (dataframe['trend_flip']) & (dataframe['trend'] == 'UP')
        dataframe['reversal_to_down'] = (dataframe['trend_flip']) & (dataframe['trend'] == 'DOWN')
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Entry logic: Enter on TEMA trend reversals
        """
        # Long entries: TEMA trend flip to UP
        dataframe.loc[
            (dataframe['reversal_to_up'] == True) &
            (~dataframe['atr'].isna()) &
            (dataframe['atr'] > 0) &
            (~dataframe['tema'].isna()),
            'enter_long'
        ] = 1

        # Short entries: TEMA trend flip to DOWN
        dataframe.loc[
            (dataframe['reversal_to_down'] == True) &
            (~dataframe['atr'].isna()) &
            (dataframe['atr'] > 0) &
            (~dataframe['tema'].isna()),
            'enter_short'
        ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Exit logic: Use custom stoploss for TP/SL management
        """
        # No exit signals here - using custom_stoploss for precise TP/SL
        dataframe['exit_long'] = 0
        dataframe['exit_short'] = 0
        return dataframe

    def custom_stoploss(self, pair: str, trade: 'Trade', current_time: datetime,
                       current_rate: float, current_profit: float, **kwargs) -> float:
        """
        Custom TP/SL logic implementing 2R:1R from Pine Script
        """
        try:
            # Get current dataframe
            dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
            
            if dataframe is None or dataframe.empty:
                return self.stoploss
            
            # Get entry parameters
            entry_price = trade.open_rate
            
            # Get latest ATR value (should be from 1m timeframe)
            latest_atr = dataframe['atr'].iloc[-1]
            
            if pd.isna(latest_atr) or latest_atr <= 0:
                logger.warning(f"Invalid ATR value for {pair}: {latest_atr}")
                return self.stoploss
            
            # Calculate risk (1R) based on ATR
            risk_amount = latest_atr * self.atr_multiplier
            
            if trade.is_short:
                # === SHORT POSITION ===
                # SL above entry (risk_amount added to entry)
                sl_price = entry_price + risk_amount
                # TP below entry (2 * risk_amount subtracted from entry)
                tp_price = entry_price - (self.tp_risk_ratio * risk_amount)
                
                # Check if TP is hit
                if current_rate <= tp_price:
                    logger.info(f"🎯 SHORT TP HIT: {pair} at {current_rate:.4f} (TP: {tp_price:.4f})")
                    return 1  # Force exit with profit
                
                # Calculate SL percentage (positive for short positions)
                sl_percentage = (sl_price - entry_price) / entry_price
                
            else:
                # === LONG POSITION ===
                # SL below entry (risk_amount subtracted from entry)
                sl_price = entry_price - risk_amount
                # TP above entry (2 * risk_amount added to entry)
                tp_price = entry_price + (self.tp_risk_ratio * risk_amount)
                
                # Check if TP is hit
                if current_rate >= tp_price:
                    logger.info(f"🎯 LONG TP HIT: {pair} at {current_rate:.4f} (TP: {tp_price:.4f})")
                    return 1  # Force exit with profit
                
                # Calculate SL percentage (negative for long positions)
                sl_percentage = -(entry_price - sl_price) / entry_price
            
            return sl_percentage
            
        except Exception as e:
            logger.error(f"Error in custom_stoploss for {pair}: {e}")
            return self.stoploss

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, entry_tag: str | None, side: str,
                 **kwargs) -> float:
        """
        Leverage management for position sizing
        """
        return 1

    def confirm_trade_entry(self, pair: str, order_type: str, amount: float,
                           rate: float, time_in_force: str, current_time: datetime,
                           entry_tag: str | None, side: str, **kwargs) -> bool:
        """
        Confirm trade entry with basic logging
        """
        try:
            # Get current market data
            dataframe, _ = self.dp.get_analyzed_dataframe(pair, self.timeframe)
            
            if dataframe is not None and not dataframe.empty:
                # Get current indicator values
                current_tema = dataframe['tema'].iloc[-1]
                current_atr = dataframe['atr'].iloc[-1]
                current_trend = dataframe['trend'].iloc[-1]
                risk_amount = current_atr * self.atr_multiplier
                
                # Calculate TP/SL levels
                if side == 'long':
                    tp_price = rate + (self.tp_risk_ratio * risk_amount)
                    sl_price = rate - risk_amount
                else:
                    tp_price = rate - (self.tp_risk_ratio * risk_amount)
                    sl_price = rate + risk_amount
                
                # Log entry information with actual data timestamp
                logger.info(f"🎯 [{current_time}] TEMA REVERSAL ENTRY: {pair} {side.upper()}")
                logger.info(f"📊 [{current_time}] Entry: {rate:.4f} | TP: {tp_price:.4f} | SL: {sl_price:.4f}")
                logger.info(f"📈 [{current_time}] TEMA: {current_tema:.4f} | ATR(1m): {current_atr:.4f} | Trend: {current_trend}")
                logger.info(f"🎲 [{current_time}] Risk: {risk_amount:.4f} | R:R = 1:{self.tp_risk_ratio}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in confirm_trade_entry for {pair}: {e}")
            return True  # Don't block trades on logging errors

    def confirm_trade_exit(self, pair: str, trade: 'Trade', order_type: str, amount: float,
                          rate: float, time_in_force: str, exit_reason: str, current_time: datetime,
                          **kwargs) -> bool:
        """
        Confirm trade exit with basic logging
        """
        try:
            # Calculate trade metrics
            entry_price = trade.open_rate
            profit_ratio = (rate - entry_price) / entry_price if not trade.is_short else (entry_price - rate) / entry_price
            
            # Determine outcome
            if profit_ratio > 0.015:  # Approximate 2R profit
                outcome = "TP"
            elif profit_ratio < -0.005:  # Approximate 1R loss
                outcome = "SL"
            else:
                outcome = "OTHER"
            
            # Calculate trade duration using actual timestamps
            trade_duration = current_time - trade.open_date
            
            # Log exit information with actual data timestamp
            logger.info(f"🏁 [{current_time}] TRADE EXIT: {pair} {trade.trade_direction.upper()}")
            logger.info(f"📊 [{current_time}] Exit: {rate:.4f} | Profit: {profit_ratio:.4%} | Outcome: {outcome}")
            logger.info(f"⏱️ [{current_time}] Duration: {trade_duration}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in confirm_trade_exit for {pair}: {e}")
            return True 