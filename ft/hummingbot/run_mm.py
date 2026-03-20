#!/usr/bin/env python3
"""
Standalone runner for Binance Perpetual Market Maker
Can be run directly without Hummingbot CLI
"""
import asyncio
import logging
import signal
import sys
from decimal import Decimal
from pathlib import Path

# Add hummingbot to path
HUMMINGBOT_PATH = Path("/allah/hummingbot")
sys.path.insert(0, str(HUMMINGBOT_PATH))

# Configuration
CONFIG = {
    "exchange": "binance_perpetual",
    "trading_pair": "ETH-USDT",
    "leverage": 125,
    "order_amount": Decimal("0.01"),   # ~$21 notional
    "bid_spread": Decimal("0.0025"),   # 0.25% spread (~$5.35 from mid)
    "ask_spread": Decimal("0.0025"),   # 0.25% spread
    "order_levels": 1,
    "order_level_spread": Decimal("0.001"),
    "order_level_amount": Decimal("1.0"),
    "order_refresh_time": 12,
    "max_position_size": Decimal("0.02"),
}


def load_credentials():
    import json
    cred_path = Path("/allah/blue/cred.json")
    with open(cred_path) as f:
        creds = json.load(f)
    return creds["binance"]["api_key"], creds["binance"]["api_secret"]


class BinancePerpMM:
    def __init__(self, api_key: str, api_secret: str, config: dict):
        self.api_key = api_key
        self.api_secret = api_secret
        self.config = config
        self.connector = None
        self.running = True
        self.logger = logging.getLogger(__name__)
        
    async def start(self):
        from hummingbot.connector.derivative.binance_perpetual.binance_perpetual_derivative import (
            BinancePerpetualDerivative
        )
        from hummingbot.core.data_type.common import PositionMode
        
        self.connector = BinancePerpetualDerivative(
            binance_perpetual_api_key=self.api_key,
            binance_perpetual_api_secret=self.api_secret,
            trading_pairs=[self.config["trading_pair"]],
            trading_required=True,
        )
        
        self.logger.info("Starting connector...")
        await self.connector.start_network()
        
        # Wait for connection
        await asyncio.sleep(3)
        
        # Set leverage and position mode
        try:
            self.connector.set_position_mode(PositionMode.ONEWAY)
            self.logger.info("Position mode set to ONEWAY")
        except Exception as e:
            self.logger.warning(f"Could not set position mode: {e}")
            
        try:
            self.connector.set_leverage(self.config["trading_pair"], self.config["leverage"])
            self.logger.info(f"Leverage set to {self.config['leverage']}x")
        except Exception as e:
            self.logger.warning(f"Could not set leverage: {e}")
        
        self.logger.info("Connector started successfully")
        
    async def stop(self):
        self.running = False
        if self.connector:
            # Cancel all orders first
            await self.cancel_all_orders()
            await self.connector.stop_network()
            self.logger.info("Connector stopped")
            
    async def cancel_all_orders(self):
        if not self.connector:
            return
        try:
            orders = self.connector.in_flight_orders
            for order_id, order in list(orders.items()):
                if order.trading_pair == self.config["trading_pair"]:
                    self.connector.cancel(self.config["trading_pair"], order_id)
                    self.logger.info(f"Cancelled: {order_id}")
            await asyncio.sleep(1)
        except Exception as e:
            self.logger.error(f"Error cancelling orders: {e}")
            
    def get_mid_price(self) -> Decimal:
        try:
            order_book = self.connector.get_order_book(self.config["trading_pair"])
            if order_book and order_book.bid_entries() and order_book.ask_entries():
                best_bid = list(order_book.bid_entries())[0].price
                best_ask = list(order_book.ask_entries())[0].price
                return (Decimal(str(best_bid)) + Decimal(str(best_ask))) / 2
        except Exception as e:
            self.logger.error(f"Error getting mid price: {e}")
        return None
    
    def get_position(self) -> Decimal:
        try:
            positions = self.connector.account_positions
            for trading_pair, pos in positions.items():
                if trading_pair == self.config["trading_pair"]:
                    return pos.amount
        except Exception:
            pass
        return Decimal("0")
    
    async def run_loop(self):
        from hummingbot.core.data_type.common import OrderType, PositionAction
        
        iteration = 0
        while self.running:
            iteration += 1
            try:
                mid_price = self.get_mid_price()
                if mid_price is None:
                    self.logger.warning("Waiting for order book...")
                    await asyncio.sleep(3)
                    continue
                
                position = self.get_position()
                
                self.logger.info("=" * 50)
                self.logger.info(f"[{iteration}] Mid: ${mid_price:.2f} | Position: {position} ETH")
                
                # Cancel existing orders
                await self.cancel_all_orders()
                
                # Place new orders
                for level in range(self.config["order_levels"]):
                    level_spread = self.config["order_level_spread"] * level
                    amount = self.config["order_amount"] * (self.config["order_level_amount"] ** level)
                    
                    buy_price = mid_price * (1 - self.config["bid_spread"] - level_spread)
                    sell_price = mid_price * (1 + self.config["ask_spread"] + level_spread)
                    
                    # Place buy order
                    try:
                        self.connector.buy(
                            trading_pair=self.config["trading_pair"],
                            amount=amount,
                            order_type=OrderType.LIMIT,
                            price=buy_price,
                            position_action=PositionAction.OPEN,
                        )
                        self.logger.info(f"  BUY  L{level}: {amount} @ ${buy_price:.2f}")
                    except Exception as e:
                        self.logger.error(f"  BUY  L{level} failed: {e}")
                    
                    # Place sell order
                    try:
                        self.connector.sell(
                            trading_pair=self.config["trading_pair"],
                            amount=amount,
                            order_type=OrderType.LIMIT,
                            price=sell_price,
                            position_action=PositionAction.OPEN,
                        )
                        self.logger.info(f"  SELL L{level}: {amount} @ ${sell_price:.2f}")
                    except Exception as e:
                        self.logger.error(f"  SELL L{level} failed: {e}")
                
                # Wait before refresh
                self.logger.info(f"Next refresh in {self.config['order_refresh_time']}s...")
                await asyncio.sleep(self.config["order_refresh_time"])
                
            except Exception as e:
                self.logger.error(f"Loop error: {e}")
                await asyncio.sleep(5)


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S"
    )
    logger = logging.getLogger(__name__)
    
    # Suppress noisy loggers
    logging.getLogger("hummingbot").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    
    api_key, api_secret = load_credentials()
    
    logger.info("=" * 60)
    logger.info("  BINANCE PERPETUAL MARKET MAKER")
    logger.info("=" * 60)
    logger.info(f"  Pair:     {CONFIG['trading_pair']}")
    logger.info(f"  Leverage: {CONFIG['leverage']}x")
    logger.info(f"  Amount:   {CONFIG['order_amount']} per level")
    logger.info(f"  Spread:   {float(CONFIG['bid_spread'])*100:.2f}% / {float(CONFIG['ask_spread'])*100:.2f}%")
    logger.info(f"  Levels:   {CONFIG['order_levels']}")
    logger.info(f"  Refresh:  {CONFIG['order_refresh_time']}s")
    logger.info("=" * 60)
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)
    
    mm = BinancePerpMM(api_key, api_secret, CONFIG)
    
    # Handle shutdown
    def shutdown(sig, frame):
        logger.info("\nShutdown signal received...")
        mm.running = False
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    try:
        await mm.start()
        await mm.run_loop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        await mm.stop()


if __name__ == "__main__":
    asyncio.run(main())
