"""CCXT WebSocket client for real-time trade streaming and candle aggregation."""

import asyncio
import logging
import time
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, Optional, Set
from dataclasses import dataclass
import ccxt.pro as ccxtpro

logger = logging.getLogger(__name__)


@dataclass
class Candle:
    symbol: str
    timestamp_ms: int
    time: datetime
    open: float
    high: float
    low: float
    close: float
    volume: float
    trade_count: int
    is_history: bool = False


class CCXTClient:
    """Async streaming client for CCXT exchanges with 5-second candle aggregation."""
    
    CANDLE_INTERVAL_MS = 5000
    MAX_TRADE_IDS = 5000
    
    def __init__(
        self,
        exchange: str,
        credentials: dict,
        symbols: list,
        timeframe_ms: int = 5000,
        history_minutes: int = 10
    ):
        self.exchange_name = exchange
        self.credentials = credentials
        self.symbols = symbols
        self.timeframe_ms = timeframe_ms
        self.history_minutes = history_minutes
        
        self._exchange: Optional[ccxtpro.Exchange] = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        
        self._trade_ids: Dict[str, Set[str]] = {s: set() for s in symbols}
        self._pending: Dict[str, Dict[int, list]] = {s: {} for s in symbols}
        self._last_boundary: Dict[str, int] = {s: 0 for s in symbols}
    
    async def _init_exchange(self) -> bool:
        try:
            exchange_class = getattr(ccxtpro, self.exchange_name)
            config = {
                **self.credentials,
                'enableRateLimit': True,
                'options': {'tradesLimit': 1000}
            }
            self._exchange = exchange_class(config)
            await self._exchange.load_markets()
            logger.info(f"Connected to {self.exchange_name}")
            return True
        except Exception as e:
            logger.error(f"Exchange init failed: {e}")
            return False
    
    async def _fetch_historical_candles(self, symbol: str) -> list:
        """Fetch historical trades and build 5s candles."""
        if self.history_minutes <= 0:
            return []
        
        try:
            since_ms = int((time.time() - self.history_minutes * 60) * 1000)
            all_trades = []
            
            # Fetch trades in batches (Binance limit is 1000)
            while True:
                trades = await self._exchange.fetch_trades(symbol, since=since_ms, limit=1000)
                if not trades:
                    break
                
                all_trades.extend(trades)
                last_ts = trades[-1]['timestamp']
                
                if last_ts >= int(time.time() * 1000) - 5000:
                    break
                since_ms = last_ts + 1
                
                if len(all_trades) > 50000:
                    break
            
            logger.info(f"{symbol}: fetched {len(all_trades)} historical trades")
            
            # Group trades by 5s boundary
            buckets: Dict[int, list] = {}
            for trade in all_trades:
                price = float(trade['price'])
                amount = float(trade['amount'])
                if price <= 0 or amount <= 0:
                    continue
                
                trade_id = str(trade['id'])
                self._trade_ids[symbol].add(trade_id)
                
                ts_ms = int(trade['timestamp'])
                boundary = self._get_boundary(ts_ms, self.timeframe_ms)
                
                if boundary not in buckets:
                    buckets[boundary] = []
                buckets[boundary].append({
                    'price': price,
                    'amount': amount,
                    'timestamp_ms': ts_ms
                })
            
            # Build candles from completed buckets
            current_ms = int(time.time() * 1000)
            current_boundary = self._get_boundary(current_ms, self.timeframe_ms)
            candles = []
            
            for boundary in sorted(buckets.keys()):
                if boundary >= current_boundary - self.timeframe_ms:
                    # Keep incomplete candles in pending for live stream
                    self._pending[symbol][boundary] = buckets[boundary]
                    continue
                
                trades = buckets[boundary]
                if not trades:
                    continue
                
                trades.sort(key=lambda t: t['timestamp_ms'])
                prices = [t['price'] for t in trades]
                volumes = [t['amount'] for t in trades]
                
                candles.append(Candle(
                    symbol=symbol,
                    timestamp_ms=boundary,
                    time=datetime.utcfromtimestamp(boundary / 1000),
                    open=prices[0],
                    high=max(prices),
                    low=min(prices),
                    close=prices[-1],
                    volume=sum(volumes),
                    trade_count=len(trades),
                    is_history=True
                ))
            
            logger.info(f"{symbol}: built {len(candles)} historical candles")
            return candles
            
        except Exception as e:
            logger.error(f"{symbol}: historical fetch failed: {e}")
            return []
    
    @staticmethod
    def _get_boundary(timestamp_ms: int, interval_ms: int = 5000) -> int:
        """
        Get the candle boundary for a given timestamp.
        
        Uses floor division to implement [T, T+interval) range:
        - Trade at T+0    → boundary T (inclusive start)
        - Trade at T+4999 → boundary T (still in range)
        - Trade at T+5000 → boundary T+5000 (exclusive end, next candle)
        
        This avoids the common "boundary error" where T+5000 would be 
        incorrectly included in the candle starting at T.
        """
        return (timestamp_ms // interval_ms) * interval_ms
    
    async def _watch_symbol(self, symbol: str):
        """Watch trades for a symbol and aggregate into candles."""
        reconnect_attempts = 0
        max_attempts = 10
        
        while self._running and reconnect_attempts < max_attempts:
            try:
                while self._running:
                    trades = await asyncio.wait_for(
                        self._exchange.watch_trades(symbol),
                        timeout=30
                    )
                    
                    for trade in trades:
                        trade_id = str(trade['id'])
                        if trade_id in self._trade_ids[symbol]:
                            continue
                        
                        self._trade_ids[symbol].add(trade_id)
                        if len(self._trade_ids[symbol]) > self.MAX_TRADE_IDS:
                            sorted_ids = sorted(self._trade_ids[symbol])
                            self._trade_ids[symbol] = set(sorted_ids[-self.MAX_TRADE_IDS//2:])
                        
                        price = float(trade['price'])
                        amount = float(trade['amount'])
                        
                        if price <= 0 or amount <= 0:
                            continue
                        
                        ts_ms = int(trade['timestamp'])
                        boundary = self._get_boundary(ts_ms, self.timeframe_ms)
                        
                        if boundary not in self._pending[symbol]:
                            self._pending[symbol][boundary] = []
                        
                        self._pending[symbol][boundary].append({
                            'price': price,
                            'amount': amount,
                            'timestamp_ms': ts_ms
                        })
                        
                        await self._emit_completed_candles(symbol)
                    
                    reconnect_attempts = 0
                    
            except asyncio.TimeoutError:
                await self._emit_completed_candles(symbol)
            except Exception as e:
                reconnect_attempts += 1
                logger.warning(f"{symbol} reconnect {reconnect_attempts}/{max_attempts}: {e}")
                if reconnect_attempts < max_attempts:
                    await asyncio.sleep(min(reconnect_attempts * 2, 30))
    
    async def _emit_completed_candles(self, symbol: str):
        """Emit only closed/completed candles."""
        current_ms = int(time.time() * 1000)
        current_boundary = self._get_boundary(current_ms, self.timeframe_ms)
        
        completed = [
            b for b in self._pending[symbol].keys()
            if b < current_boundary - self.timeframe_ms
        ]
        
        for boundary in sorted(completed):
            trades = self._pending[symbol].pop(boundary)
            if not trades:
                continue
            
            trades.sort(key=lambda t: t['timestamp_ms'])
            prices = [t['price'] for t in trades]
            volumes = [t['amount'] for t in trades]
            
            candle = Candle(
                symbol=symbol,
                timestamp_ms=boundary,
                time=datetime.utcfromtimestamp(boundary / 1000),
                open=prices[0],
                high=max(prices),
                low=min(prices),
                close=prices[-1],
                volume=sum(volumes),
                trade_count=len(trades),
                is_history=False
            )
            
            await self._queue.put(candle)
            self._last_boundary[symbol] = boundary
    
    async def stream(self) -> AsyncGenerator[Candle, None]:
        """Stream completed 5-second candles as an async generator."""
        if not await self._init_exchange():
            return
        
        # Fetch and yield historical candles first
        for symbol in self.symbols:
            historical = await self._fetch_historical_candles(symbol)
            for candle in historical:
                yield candle
        
        self._running = True
        
        tasks = [
            asyncio.create_task(self._watch_symbol(symbol))
            for symbol in self.symbols
        ]
        
        try:
            while self._running:
                try:
                    candle = await asyncio.wait_for(self._queue.get(), timeout=1)
                    yield candle
                except asyncio.TimeoutError:
                    continue
        finally:
            self._running = False
            for task in tasks:
                task.cancel()
            if self._exchange:
                await self._exchange.close()
    
    async def close(self):
        """Close the client and exchange connection."""
        self._running = False
        if self._exchange:
            await self._exchange.close()
