#!/usr/bin/env python3
"""
Direct Binance Perpetual Market Maker
Uses Binance API directly for reliable order management
"""
import asyncio
import hmac
import hashlib
import json
import logging
import signal
import time
from decimal import Decimal, ROUND_DOWN
from pathlib import Path

import aiohttp

# Configuration
CONFIG = {
    "symbol": "ETHUSDT",
    "leverage": 125,
    "order_qty": "0.01",           # ETH
    "bid_spread": 0.0025,          # 0.25% below mid
    "ask_spread": 0.0025,          # 0.25% above mid
    "refresh_seconds": 10,
    "tick_size": "0.01",           # Price tick
    "qty_precision": 3,            # Qty decimal places
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("MM")


class BinanceMM:
    BASE_URL = "https://fapi.binance.com"
    
    def __init__(self):
        creds = json.loads(Path("/allah/blue/cred.json").read_text())
        self.api_key = creds["binance"]["api_key"]
        self.api_secret = creds["binance"]["api_secret"]
        self.running = True
        self.session = None
        self.open_orders = {}
        
    def sign(self, params: str) -> str:
        return hmac.new(
            self.api_secret.encode(), 
            params.encode(), 
            hashlib.sha256
        ).hexdigest()
    
    async def request(self, method: str, endpoint: str, params: dict = None, signed: bool = False):
        if params is None:
            params = {}
        
        if signed:
            params["timestamp"] = int(time.time() * 1000)
            query = "&".join(f"{k}={v}" for k, v in params.items())
            params["signature"] = self.sign(query)
        
        headers = {"X-MBX-APIKEY": self.api_key}
        url = f"{self.BASE_URL}{endpoint}"
        
        async with self.session.request(method, url, params=params, headers=headers) as resp:
            data = await resp.json()
            if resp.status != 200:
                log.error(f"API Error: {data}")
            return data, resp.status
    
    async def get_price(self) -> float:
        data, _ = await self.request("GET", "/fapi/v1/ticker/price", {"symbol": CONFIG["symbol"]})
        return float(data["price"])
    
    async def get_position(self) -> dict:
        data, _ = await self.request("GET", "/fapi/v2/positionRisk", {"symbol": CONFIG["symbol"]}, signed=True)
        for p in data:
            if p["symbol"] == CONFIG["symbol"]:
                return {
                    "qty": float(p["positionAmt"]),
                    "pnl": float(p["unRealizedProfit"]),
                    "entry": float(p["entryPrice"]) if float(p["positionAmt"]) != 0 else 0
                }
        return {"qty": 0, "pnl": 0, "entry": 0}
    
    async def get_balance(self) -> float:
        data, _ = await self.request("GET", "/fapi/v2/balance", signed=True)
        for b in data:
            if b["asset"] == "USDT":
                return float(b["balance"])
        return 0
    
    async def cancel_all(self):
        data, status = await self.request(
            "DELETE", "/fapi/v1/allOpenOrders",
            {"symbol": CONFIG["symbol"]}, signed=True
        )
        if status == 200:
            log.info("Cancelled all orders")
        return status == 200
    
    async def place_order(self, side: str, price: float, qty: str) -> dict:
        # Round price to tick size
        tick = Decimal(CONFIG["tick_size"])
        price_dec = Decimal(str(price)).quantize(tick, rounding=ROUND_DOWN)
        
        params = {
            "symbol": CONFIG["symbol"],
            "side": side,
            "type": "LIMIT",
            "timeInForce": "GTC",
            "quantity": qty,
            "price": str(price_dec),
        }
        
        data, status = await self.request("POST", "/fapi/v1/order", params, signed=True)
        
        if status == 200:
            log.info(f"  {side:4} {qty} @ ${price_dec}")
            return data
        else:
            log.error(f"  {side} failed: {data.get('msg', data)}")
            return None
    
    async def set_leverage(self):
        data, _ = await self.request(
            "POST", "/fapi/v1/leverage",
            {"symbol": CONFIG["symbol"], "leverage": CONFIG["leverage"]},
            signed=True
        )
        log.info(f"Leverage set to {CONFIG['leverage']}x")
    
    async def run(self):
        self.session = aiohttp.ClientSession()
        
        try:
            # Setup
            await self.set_leverage()
            balance = await self.get_balance()
            log.info(f"Balance: ${balance:.4f} USDT")
            log.info(f"Spread: {CONFIG['bid_spread']*100:.2f}% / {CONFIG['ask_spread']*100:.2f}%")
            log.info("=" * 50)
            
            iteration = 0
            while self.running:
                iteration += 1
                
                try:
                    # Get current state
                    price = await self.get_price()
                    pos = await self.get_position()
                    
                    log.info(f"[{iteration}] Price: ${price:.2f} | Pos: {pos['qty']} | PnL: ${pos['pnl']:.4f}")
                    
                    # Cancel existing orders
                    await self.cancel_all()
                    await asyncio.sleep(0.5)
                    
                    # Calculate order prices
                    bid_price = price * (1 - CONFIG["bid_spread"])
                    ask_price = price * (1 + CONFIG["ask_spread"])
                    
                    # Place new orders
                    await self.place_order("BUY", bid_price, CONFIG["order_qty"])
                    await self.place_order("SELL", ask_price, CONFIG["order_qty"])
                    
                    # Show spread
                    spread_pct = (ask_price - bid_price) / price * 100
                    spread_usd = ask_price - bid_price
                    log.info(f"  Spread: {spread_pct:.2f}% (${spread_usd:.2f})")
                    
                    # Wait
                    log.info(f"  Next refresh in {CONFIG['refresh_seconds']}s...")
                    await asyncio.sleep(CONFIG["refresh_seconds"])
                    
                except Exception as e:
                    log.error(f"Error: {e}")
                    await asyncio.sleep(3)
                    
        finally:
            # Cleanup
            log.info("Shutting down...")
            await self.cancel_all()
            balance = await self.get_balance()
            log.info(f"Final balance: ${balance:.4f} USDT")
            await self.session.close()


async def main():
    mm = BinanceMM()
    
    def shutdown(sig, frame):
        log.info("\nStop signal received")
        mm.running = False
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    log.info("=" * 50)
    log.info("  BINANCE PERP MARKET MAKER (Direct API)")
    log.info("=" * 50)
    log.info(f"  Symbol:  {CONFIG['symbol']}")
    log.info(f"  Qty:     {CONFIG['order_qty']}")
    log.info(f"  Spread:  {CONFIG['bid_spread']*100:.2f}% / {CONFIG['ask_spread']*100:.2f}%")
    log.info("=" * 50)
    
    await mm.run()


if __name__ == "__main__":
    asyncio.run(main())
