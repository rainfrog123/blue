"""
TestExecution Strategy - Frequent trigger for testing order execution

Based on SpreadCapture but with very simple entry conditions that trigger often.
Use this to test limit order placement, Post-Only, adjust_entry_price, etc.

Entry triggers:
- Long: When close > open (green candle)
- Short: When close < open (red candle)

This will trigger almost every candle for rapid testing.
"""

from datetime import datetime, timedelta
from pandas import DataFrame
import logging
from freqtrade.strategy import IStrategy
from freqtrade.persistence import Trade, Order

logger = logging.getLogger(__name__)


class TestExecution(IStrategy):
    """
    Simple test strategy that triggers entries frequently.
    
    Entry: Every green candle = long, every red candle = short
    Exit: TP at 0.05% or SL at 0.05%
    
    Use max_open_trades=1 in config to test one trade at a time.
    """
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 10
    
    # Warmup: wait N seconds before allowing trades
    warmup_seconds = 15
    _start_time = None
    
    # Tight SL for quick test cycles
    stoploss = -0.05  # 5% account loss (small for testing)
    trailing_stop = False
    use_custom_stoploss = False
    
    # ROI disabled - using custom_exit
    minimal_roi = {"0": 100}
    
    # Strategy parameters
    tp_percent = 0.05  # 5% account profit target
    max_chase_minutes = 2  # Short chase time for testing
    target_leverage = 10  # Lower leverage for testing
    
    # Order types - limit with Post-Only
    order_types = {
        "entry": "limit",
        "exit": "limit",
        "stoploss": "market",
        "stoploss_on_exchange": False,
    }
    
    order_time_in_force = {
        "entry": "PO",  # Post-Only = maker fees
        "exit": "PO",
    }

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Minimal indicators - just need candle color."""
        # Green candle = bullish, Red candle = bearish
        dataframe['is_green'] = dataframe['close'] > dataframe['open']
        dataframe['is_red'] = dataframe['close'] < dataframe['open']
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Simple entries - triggers on almost every candle.
        
        Long: Green candle (close > open)
        Short: Red candle (close < open)
        """
        
        # Long on green candle
        dataframe.loc[
            (dataframe['is_green']) &
            (dataframe['volume'] > 0),
            'enter_long'
        ] = 1
        
        # Short on red candle
        dataframe.loc[
            (dataframe['is_red']) &
            (dataframe['volume'] > 0),
            'enter_short'
        ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """No signal exits - only TP/SL."""
        return dataframe

    def custom_exit(self, pair: str, trade: Trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs) -> str | None:
        """Take profit at target."""
        if current_profit >= self.tp_percent:
            return 'tp_target'
        return None

    def custom_exit_price(self, pair: str, trade: Trade, current_time: datetime,
                          proposed_rate: float, current_profit: float,
                          exit_tag: str | None, **kwargs) -> float:
        """Exit at TP target price."""
        if trade.is_short:
            tp_price = trade.open_rate * (1 - self.tp_percent)
        else:
            tp_price = trade.open_rate * (1 + self.tp_percent)
        return tp_price

    def adjust_entry_price(
        self,
        trade: Trade,
        order: Order | None,
        pair: str,
        current_time: datetime,
        proposed_rate: float,
        current_order_rate: float,
        entry_tag: str | None,
        side: str,
        **kwargs,
    ) -> float | None:
        """
        Chase entry orders - adjust to current market price.
        """
        if order is None:
            return proposed_rate
        
        order_age = current_time - order.order_date_utc
        max_chase = timedelta(minutes=self.max_chase_minutes)
        
        if order_age > max_chase:
            logger.info(f"⏰ Entry timeout for {pair} after {order_age}")
            return None  # Cancel
        
        # Always chase - adjust if price moved at all
        price_diff = abs(proposed_rate - current_order_rate) / current_order_rate
        
        if price_diff > 0.0001:  # 0.01% threshold (very sensitive)
            logger.info(f"🔄 Chasing entry {pair}: {current_order_rate:.4f} -> {proposed_rate:.4f}")
            return proposed_rate
        
        return current_order_rate

    def adjust_exit_price(
        self,
        trade: Trade,
        order: Order | None,
        pair: str,
        current_time: datetime,
        proposed_rate: float,
        current_order_rate: float,
        entry_tag: str | None,
        side: str,
        **kwargs,
    ) -> float | None:
        """
        Adjust exit orders to TP target.
        """
        if order is None or trade is None:
            return proposed_rate
        
        if trade.is_short:
            tp_price = trade.open_rate * (1 - self.tp_percent)
            target = min(proposed_rate, tp_price)
        else:
            tp_price = trade.open_rate * (1 + self.tp_percent)
            target = max(proposed_rate, tp_price)
        
        price_diff = abs(target - current_order_rate) / current_order_rate
        
        if price_diff > 0.0001:
            logger.info(f"🎯 Adjusting exit {pair}: {current_order_rate:.4f} -> {target:.4f}")
            return target
        
        return current_order_rate

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, 
                 entry_tag: str | None, side: str, **kwargs) -> float:
        """Use test leverage (10x)."""
        return min(self.target_leverage, max_leverage)

    def confirm_trade_entry(self, pair: str, order_type: str, amount: float,
                            rate: float, time_in_force: str, current_time: datetime,
                            entry_tag: str | None, side: str, **kwargs) -> bool:
        """Log entry - block during warmup period."""
        # Initialize start time on first call
        if self._start_time is None:
            self._start_time = current_time
            logger.info(f"⏳ Warmup started - waiting {self.warmup_seconds}s before trading")
        
        # Block entries during warmup
        elapsed = (current_time - self._start_time).total_seconds()
        if elapsed < self.warmup_seconds:
            remaining = self.warmup_seconds - elapsed
            logger.info(f"⏳ Warmup: {remaining:.1f}s remaining - blocking entry")
            return False
        
        logger.info(f"📈 TEST ENTRY {side.upper()} {pair} @ {rate:.4f} ({order_type}, {time_in_force})")
        return True

    def confirm_trade_exit(self, pair: str, trade: Trade, order_type: str,
                           amount: float, rate: float, time_in_force: str,
                           exit_reason: str, current_time: datetime, **kwargs) -> bool:
        """Log exit."""
        profit = trade.calc_profit_ratio(rate)
        logger.info(f"📉 TEST EXIT {trade.trade_direction.upper()} {pair} @ {rate:.4f} | "
                   f"Profit: {profit:.2%} | Reason: {exit_reason}")
        return True

