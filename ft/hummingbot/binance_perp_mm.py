"""
Binance Perpetual USDT Market Maker
Based on Hummingbot V2 Strategy Framework
"""
import logging
import os
from decimal import Decimal
from typing import Dict, List

from pydantic import Field

from hummingbot.connector.connector_base import ConnectorBase
from hummingbot.core.data_type.common import MarketDict, OrderType, PositionMode, PriceType, TradeType
from hummingbot.core.data_type.order_candidate import OrderCandidate
from hummingbot.core.event.events import OrderFilledEvent
from hummingbot.strategy.strategy_v2_base import StrategyV2Base, StrategyV2ConfigBase


class BinancePerpMMConfig(StrategyV2ConfigBase):
    script_file_name: str = os.path.basename(__file__)
    controllers_config: List[str] = []
    
    # Exchange settings
    exchange: str = Field(default="binance_perpetual", description="Connector name")
    trading_pair: str = Field(default="ETH-USDT", description="Trading pair")
    
    # Position settings
    leverage: int = Field(default=125, ge=1, le=125, description="Leverage multiplier")
    order_amount: Decimal = Field(default=Decimal("0.01"), description="Order size in base asset")
    
    # Spread settings
    bid_spread: Decimal = Field(default=Decimal("0.0005"), description="Bid spread from mid price (0.05%)")
    ask_spread: Decimal = Field(default=Decimal("0.0005"), description="Ask spread from mid price (0.05%)")
    
    # Order management
    order_refresh_time: int = Field(default=15, description="Seconds between order refresh")
    order_levels: int = Field(default=3, description="Number of order levels on each side")
    order_level_spread: Decimal = Field(default=Decimal("0.0003"), description="Spread between levels")
    order_level_amount: Decimal = Field(default=Decimal("1.0"), description="Amount multiplier per level")
    
    # Risk management
    max_position_size: Decimal = Field(default=Decimal("1.0"), description="Max position size in base")
    stop_loss_pct: Decimal = Field(default=Decimal("0.02"), description="Stop loss percentage")
    take_profit_pct: Decimal = Field(default=Decimal("0.01"), description="Take profit percentage")
    
    # Price source
    price_type: str = Field(default="mid", description="Price source: mid or last")

    def update_markets(self, markets: MarketDict) -> MarketDict:
        markets[self.exchange] = markets.get(self.exchange, set()) | {self.trading_pair}
        return markets


class BinancePerpMM(StrategyV2Base):
    """
    Market Making Strategy for Binance Perpetual USDT
    
    Features:
    - Multi-level order placement
    - Dynamic spread adjustment
    - Position tracking and risk management
    - Leverage support
    """
    
    create_timestamp = 0
    price_source = PriceType.MidPrice
    
    def __init__(self, connectors: Dict[str, ConnectorBase], config: BinancePerpMMConfig):
        super().__init__(connectors, config)
        self.config = config
        self.price_source = PriceType.LastTrade if self.config.price_type == "last" else PriceType.MidPrice
        self._position_initialized = False
        
    def on_tick(self):
        if not self._position_initialized:
            self._initialize_position_settings()
            self._position_initialized = True
            
        if self.create_timestamp <= self.current_timestamp:
            self.cancel_all_orders()
            
            # Check position limits before placing orders
            if self._check_position_limits():
                proposal: List[OrderCandidate] = self.create_proposal()
                proposal_adjusted: List[OrderCandidate] = self.adjust_proposal_to_budget(proposal)
                self.place_orders(proposal_adjusted)
            
            self.create_timestamp = self.config.order_refresh_time + self.current_timestamp
    
    def _initialize_position_settings(self):
        """Initialize leverage and position mode on the exchange."""
        connector = self.connectors[self.config.exchange]
        try:
            connector.set_position_mode(PositionMode.ONEWAY)
            connector.set_leverage(self.config.trading_pair, self.config.leverage)
            self.log_with_clock(logging.INFO, 
                f"Initialized: Leverage={self.config.leverage}x, Mode=ONEWAY")
        except Exception as e:
            self.log_with_clock(logging.WARNING, f"Position settings error: {e}")
    
    def _check_position_limits(self) -> bool:
        """Check if current position is within limits."""
        connector = self.connectors[self.config.exchange]
        positions = connector.account_positions
        
        for trading_pair, position in positions.items():
            if trading_pair == self.config.trading_pair:
                position_size = abs(position.amount)
                if position_size >= self.config.max_position_size:
                    self.log_with_clock(logging.WARNING, 
                        f"Max position reached: {position_size} >= {self.config.max_position_size}")
                    return False
        return True
    
    def _get_current_position(self) -> Decimal:
        """Get current position size (positive for long, negative for short)."""
        connector = self.connectors[self.config.exchange]
        positions = connector.account_positions
        
        for trading_pair, position in positions.items():
            if trading_pair == self.config.trading_pair:
                return position.amount
        return Decimal("0")

    def create_proposal(self) -> List[OrderCandidate]:
        """Create multi-level order proposal."""
        ref_price = self.connectors[self.config.exchange].get_price_by_type(
            self.config.trading_pair, self.price_source
        )
        
        orders = []
        current_position = self._get_current_position()
        
        for level in range(self.config.order_levels):
            level_spread = self.config.order_level_spread * level
            level_amount = self.config.order_amount * (self.config.order_level_amount ** level)
            
            # Calculate prices
            buy_spread = self.config.bid_spread + level_spread
            sell_spread = self.config.ask_spread + level_spread
            
            buy_price = ref_price * (1 - buy_spread)
            sell_price = ref_price * (1 + sell_spread)
            
            # Adjust amounts based on current position to stay within limits
            remaining_buy_capacity = self.config.max_position_size - current_position
            remaining_sell_capacity = self.config.max_position_size + current_position
            
            buy_amount = min(level_amount, remaining_buy_capacity)
            sell_amount = min(level_amount, remaining_sell_capacity)
            
            if buy_amount > 0:
                buy_order = OrderCandidate(
                    trading_pair=self.config.trading_pair,
                    is_maker=True,
                    order_type=OrderType.LIMIT,
                    order_side=TradeType.BUY,
                    amount=Decimal(buy_amount),
                    price=buy_price
                )
                orders.append(buy_order)
            
            if sell_amount > 0:
                sell_order = OrderCandidate(
                    trading_pair=self.config.trading_pair,
                    is_maker=True,
                    order_type=OrderType.LIMIT,
                    order_side=TradeType.SELL,
                    amount=Decimal(sell_amount),
                    price=sell_price
                )
                orders.append(sell_order)
        
        return orders

    def adjust_proposal_to_budget(self, proposal: List[OrderCandidate]) -> List[OrderCandidate]:
        """Adjust orders to available budget."""
        return self.connectors[self.config.exchange].budget_checker.adjust_candidates(
            proposal, all_or_none=False
        )

    def place_orders(self, proposal: List[OrderCandidate]) -> None:
        """Place all orders in proposal."""
        for order in proposal:
            self.place_order(connector_name=self.config.exchange, order=order)

    def place_order(self, connector_name: str, order: OrderCandidate):
        """Place a single order."""
        if order.order_side == TradeType.SELL:
            self.sell(
                connector_name=connector_name,
                trading_pair=order.trading_pair,
                amount=order.amount,
                order_type=order.order_type,
                price=order.price
            )
        elif order.order_side == TradeType.BUY:
            self.buy(
                connector_name=connector_name,
                trading_pair=order.trading_pair,
                amount=order.amount,
                order_type=order.order_type,
                price=order.price
            )

    def cancel_all_orders(self):
        """Cancel all active orders."""
        for order in self.get_active_orders(connector_name=self.config.exchange):
            self.cancel(self.config.exchange, order.trading_pair, order.client_order_id)

    def did_fill_order(self, event: OrderFilledEvent):
        """Handle order fill events."""
        msg = (
            f"{event.trade_type.name} {round(event.amount, 6)} "
            f"{event.trading_pair} @ {round(event.price, 2)} "
            f"[{self.config.exchange}]"
        )
        self.log_with_clock(logging.INFO, msg)
        self.notify_hb_app_with_timestamp(msg)
