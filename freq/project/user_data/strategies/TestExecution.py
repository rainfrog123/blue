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
    process_only_new_candles = True  # Allow same-bar exit order placement
    startup_candle_count: int = 10
    
    # Tight SL for quick test cycles
    stoploss = -0.10  # 0.1% price move = 15% account loss at 150x
    trailing_stop = False
    use_custom_stoploss = False
    
    # ROI disabled - using custom_exit
    minimal_roi = {"0": 100}
    
    # Strategy parameters
    tp_price_pct = 0.001  # 0.1% price move = 15% account profit at 150x
    max_chase_minutes = 2  # Short chase time for testing
    target_leverage = 150  # High leverage for testing
    trade_cooldown_minutes = 5  # Wait 5 min between trades
    
    # Track last trade time
    _last_trade_time: datetime | None = None
    
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
        pair = metadata.get('pair', 'unknown')
        
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
        """No signal exits - use custom_exit or stoploss only."""
        # Don't set exit signals here - they block entries!
        # Exit is handled by custom_exit when trade exists
        return dataframe

    def custom_exit(self, pair: str, trade: Trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs) -> str | bool:
        """Signal exit only if no exit order already open."""
        # Check if there's already an open exit order - don't re-signal
        # ft_order_side is 'buy'/'sell', compare with trade.exit_side
        for order in trade.open_orders:
            if order.ft_order_side == trade.exit_side:
                return False  # Exit order already pending, don't replace it
        
        logger.info(f"🎯 Placing TP order for {pair}")
        return 'tp_target'  # Place TP order

    def custom_exit_price(self, pair: str, trade: Trade, current_time: datetime,
                          proposed_rate: float, current_profit: float,
                          exit_tag: str | None, **kwargs) -> float:
        """Exit at TP target price - order placed immediately at this price."""
        if trade.is_short:
            tp_price = trade.open_rate * (1 - self.tp_price_pct)  # 0.1% below entry
        else:
            tp_price = trade.open_rate * (1 + self.tp_price_pct)  # 0.1% above entry
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
        Keep exit order at TP price - don't adjust unless way off.
        """
        if order is None or trade is None:
            return proposed_rate
        
        # Keep existing order - don't chase exit price
        return current_order_rate

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, 
                 entry_tag: str | None, side: str, **kwargs) -> float:
        """Use test leverage (10x)."""
        return min(self.target_leverage, max_leverage)

    def confirm_trade_entry(self, pair: str, order_type: str, amount: float,
                            rate: float, time_in_force: str, current_time: datetime,
                            entry_tag: str | None, side: str, **kwargs) -> bool:
        """Log entry - cooldown disabled for testing."""
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

