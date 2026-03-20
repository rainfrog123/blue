"""
SpreadCapture Strategy (5s timeframe + 1m HTF filter)

Based on TemaSlope with limit order management for maker fee capture.
Uses TEMA slope reversals as entry signals with 1m higher timeframe
trend confirmation (must be 3+ bars in same direction).

Config: live_spread_capture.json
- timeframe: 5s (high frequency)
- leverage: 125x
- HTF filter: 1m trend must align + be 3+ bars long
- entry: limit orders at bid (Post-Only)
- exit TP: 0.1% price move = 12.5% account profit
- exit SL: 0.1% price move = 12.5% account loss
- Risk/Reward: 1:1
"""

from datetime import datetime, timedelta
from pandas import DataFrame
import numpy as np
import talib.abstract as ta
import logging
from freqtrade.strategy import IStrategy, informative
from freqtrade.persistence import Trade, Order

logger = logging.getLogger(__name__)


class SpreadCapture(IStrategy):
    """
    TEMA slope reversal strategy optimized for limit order spread capture.
    
    Entry: 5s TEMA slope reversal + 1m trend confirmation (3+ bars)
    Exit: TP or SL at 0.1% price move (12.5% account at 125x)
    
    Leverage: 125x
    - SL: 0.1% price move = 12.5% account loss (~$2.95 for ETH)
    - TP: 0.1% price move = 12.5% account gain (~$2.95 for ETH)
    
    HTF Filter:
    - Long: 1m TEMA slope UP for at least 3 bars
    - Short: 1m TEMA slope DOWN for at least 3 bars
    
    Order Management:
    - Entry: limit orders at bid (Post-Only = maker fees)
    - Exit TP: limit orders at ask (Post-Only = maker fees)  
    - Exit SL: market order at 12.5% loss
    - adjust_entry_price chases the best bid
    - adjust_exit_price maintains TP target
    """
    
    INTERFACE_VERSION = 3
    timeframe = '5s'
    can_short: bool = True
    process_only_new_candles = True
    startup_candle_count: int = 150  # More candles needed for 5s
    
    # Stoploss - 0.1% price move at 125x = 12.5% account loss
    # For ETH at $2950 = ~$2.95 price move triggers SL
    stoploss = -0.125  # 12.5% account loss (= 0.1% price move × 125x)
    trailing_stop = False
    use_custom_stoploss = False
    
    # ROI disabled - using custom_exit for TP only
    minimal_roi = {"0": 100}
    
    # Strategy parameters
    tema_period = 50
    tp_percent = 0.125  # 12.5% account gain (= 0.1% price move × 125x)
    max_chase_minutes = 10  # Max time to chase entry order
    min_htf_trend_bars = 3  # Minimum bars for 1m trend confirmation
    target_leverage = 125  # Max leverage
    
    # Order types configured in strategy (backup if not in config)
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

    @informative('1m')
    def populate_indicators_1m(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Calculate TEMA trend on 1m timeframe for higher timeframe confirmation.
        Columns will be available as tema_slope_1m, trend_duration_1m, etc.
        """
        # TEMA calculation on 1m
        ema1 = ta.EMA(dataframe['close'], timeperiod=self.tema_period)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_period)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_period)
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        # TEMA slope: 1=UP, -1=DOWN
        dataframe['tema_slope'] = 0
        dataframe.loc[dataframe['tema'] > dataframe['tema'].shift(1), 'tema_slope'] = 1
        dataframe.loc[dataframe['tema'] < dataframe['tema'].shift(1), 'tema_slope'] = -1
        
        # Track trend duration (how many bars in same direction)
        # Create trend change marker
        dataframe['trend_change'] = (dataframe['tema_slope'] != dataframe['tema_slope'].shift(1)).astype(int)
        dataframe['trend_group'] = dataframe['trend_change'].cumsum()
        dataframe['trend_duration'] = dataframe.groupby('trend_group').cumcount() + 1
        
        return dataframe

    def populate_indicators(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """Calculate TEMA and slope indicators."""
        
        # TEMA calculation: 3*EMA1 - 3*EMA2 + EMA3
        ema1 = ta.EMA(dataframe['close'], timeperiod=self.tema_period)
        ema2 = ta.EMA(ema1, timeperiod=self.tema_period)
        ema3 = ta.EMA(ema2, timeperiod=self.tema_period)
        dataframe['tema'] = 3 * ema1 - 3 * ema2 + ema3
        
        # TEMA slope: 1=UP, -1=DOWN, 0=FLAT
        dataframe['tema_slope'] = 0
        dataframe.loc[dataframe['tema'] > dataframe['tema'].shift(1), 'tema_slope'] = 1
        dataframe.loc[dataframe['tema'] < dataframe['tema'].shift(1), 'tema_slope'] = -1
        
        # Slope change detection
        dataframe['slope_prev'] = dataframe['tema_slope'].shift(1)
        dataframe['slope_change_up'] = (dataframe['tema_slope'] == 1) & (dataframe['slope_prev'] <= 0)
        dataframe['slope_change_down'] = (dataframe['tema_slope'] == -1) & (dataframe['slope_prev'] >= 0)
        
        return dataframe

    def populate_entry_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """
        Entry signals based on TEMA slope reversals with 1m HTF confirmation.
        
        Long: 5s slope changes to UP + 1m trend UP for at least 3 bars
        Short: 5s slope changes to DOWN + 1m trend DOWN for at least 3 bars
        """
        
        # Higher timeframe (1m) conditions
        # tema_slope_1m: 1=UP, -1=DOWN
        # trend_duration_1m: number of bars in current trend direction
        htf_uptrend = (
            (dataframe['tema_slope_1m'] == 1)
            # & (dataframe['trend_duration_1m'] >= self.min_htf_trend_bars)  # Disabled: no min bars
        )
        htf_downtrend = (
            (dataframe['tema_slope_1m'] == -1)
            # & (dataframe['trend_duration_1m'] >= self.min_htf_trend_bars)  # Disabled: no min bars
        )
        
        # Long: 5s TEMA slope changes to UP + 1m uptrend (3+ bars)
        dataframe.loc[
            (dataframe['slope_change_up']) &
            (htf_uptrend) &
            (dataframe['volume'] > 0),
            'enter_long'
        ] = 1
        
        # Short: 5s TEMA slope changes to DOWN + 1m downtrend (3+ bars)
        dataframe.loc[
            (dataframe['slope_change_down']) &
            (htf_downtrend) &
            (dataframe['volume'] > 0),
            'enter_short'
        ] = 1
        
        return dataframe

    def populate_exit_trend(self, dataframe: DataFrame, metadata: dict) -> DataFrame:
        """No exit signals - exits only via TP (limit) or SL (market)."""
        # Disabled - using only:
        # - TP: custom_exit at 0.2% profit (limit order)
        # - SL: stoploss at 0.1% loss (market order)
        return dataframe

    def custom_exit(self, pair: str, trade: Trade, current_time: datetime,
                    current_rate: float, current_profit: float, **kwargs) -> str | None:
        """
        Custom exit logic - take profit at target.
        This triggers placing a limit exit order.
        """
        # Check if we've reached TP target
        if current_profit >= self.tp_percent:
            return 'tp_target'
        
        return None

    def custom_exit_price(self, pair: str, trade: Trade, current_time: datetime,
                          proposed_rate: float, current_profit: float,
                          exit_tag: str | None, **kwargs) -> float:
        """
        Custom exit price - place limit order at TP target level.
        """
        if trade.is_short:
            # Short: TP is below entry
            tp_price = trade.open_rate * (1 - self.tp_percent)
        else:
            # Long: TP is above entry
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
        Continuously adjust unfilled entry limit orders to chase the market.
        
        Called every candle for unfilled entry orders.
        - proposed_rate: Current market price from entry_pricing config (best bid)
        - current_order_rate: Price of existing order
        
        Returns:
        - proposed_rate: Cancel and replace at new market price
        - current_order_rate: Keep existing order
        - None: Cancel order without replacement
        """
        if order is None:
            return proposed_rate
        
        # Calculate how long we've been chasing
        order_age = current_time - order.order_date_utc
        max_chase = timedelta(minutes=self.max_chase_minutes)
        
        # Give up after max chase time
        if order_age > max_chase:
            logger.info(f"Entry order chase timeout for {pair} after {order_age}")
            return None  # Cancel, don't replace
        
        # Check if price moved significantly (> 0.05%)
        price_diff = abs(proposed_rate - current_order_rate) / current_order_rate
        
        if price_diff > 0.0005:  # 0.05% threshold
            logger.debug(f"Adjusting entry for {pair}: {current_order_rate:.4f} -> {proposed_rate:.4f}")
            return proposed_rate  # Replace at new price
        
        # Keep existing order
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
        Adjust unfilled exit limit orders.
        
        For exits, we want to place at our TP target, not chase the market.
        But if the market moved favorably, we can adjust.
        """
        if order is None or trade is None:
            return proposed_rate
        
        # Calculate TP target price
        if trade.is_short:
            tp_price = trade.open_rate * (1 - self.tp_percent)
            # For shorts, lower is better - use min of proposed and TP
            target = min(proposed_rate, tp_price)
        else:
            tp_price = trade.open_rate * (1 + self.tp_percent)
            # For longs, higher is better - use max of proposed and TP
            target = max(proposed_rate, tp_price)
        
        # Check if adjustment needed
        price_diff = abs(target - current_order_rate) / current_order_rate
        
        if price_diff > 0.0005:  # 0.05% threshold
            logger.debug(f"Adjusting exit for {pair}: {current_order_rate:.4f} -> {target:.4f}")
            return target
        
        return current_order_rate

    def leverage(self, pair: str, current_time: datetime, current_rate: float,
                 proposed_leverage: float, max_leverage: float, 
                 entry_tag: str | None, side: str, **kwargs) -> float:
        """Use max leverage (125x)."""
        return min(self.target_leverage, max_leverage)

    def confirm_trade_entry(self, pair: str, order_type: str, amount: float,
                            rate: float, time_in_force: str, current_time: datetime,
                            entry_tag: str | None, side: str, **kwargs) -> bool:
        """Log entry confirmation."""
        logger.info(f"📈 ENTRY {side.upper()} {pair} @ {rate:.4f} ({order_type}, {time_in_force})")
        return True

    def confirm_trade_exit(self, pair: str, trade: Trade, order_type: str,
                           amount: float, rate: float, time_in_force: str,
                           exit_reason: str, current_time: datetime, **kwargs) -> bool:
        """Log exit confirmation."""
        profit = trade.calc_profit_ratio(rate)
        logger.info(f"📉 EXIT {trade.trade_direction.upper()} {pair} @ {rate:.4f} | "
                   f"Profit: {profit:.2%} | Reason: {exit_reason}")
        return True

