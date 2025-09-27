#!/usr/bin/env python3
import asyncio
import logging
import time
import signal
import numpy as np
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List, Optional
import ccxt.pro as ccxtpro
from dataclasses import dataclass
from asyncio import Queue, Semaphore

from database import MarketDatabase
from settings import EXCHANGE, EXCHANGE_CREDENTIALS, SYMBOLS, LOG_LEVEL, LOG_FILE

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger(__name__)

CANDLE_INTERVAL_MS = 5000
TRADE_BUFFER_SIZE = 2000
QUEUE_SIZE = 10000
BATCH_SIZE = 25
MAX_TRADE_IDS = 5000

@dataclass
class RawTrade:
    id: str
    timestamp_ms: int
    price: float
    amount: float
    symbol: str
    side: str

@dataclass
class Candle:
    timestamp_ms: int
    open: float
    high: float
    low: float
    close: float
    volume: float
    trade_count: int
    symbol: str

class DataCollector:
    def __init__(self):
        self.db = MarketDatabase()
        self.exchange = None
        self.running = False
        
        self.trade_queues = {symbol: Queue(maxsize=QUEUE_SIZE) for symbol in SYMBOLS}
        self.candle_queues = {symbol: Queue(maxsize=QUEUE_SIZE) for symbol in SYMBOLS}
        self.trade_buffers = {symbol: deque(maxlen=TRADE_BUFFER_SIZE) for symbol in SYMBOLS}
        self.trade_id_sets = {symbol: set() for symbol in SYMBOLS}
        self.pending_candles = {symbol: {} for symbol in SYMBOLS}
        
        self.stats = defaultdict(int)
        self.db_semaphore = Semaphore(3)
        
        signal.signal(signal.SIGINT, lambda s, f: setattr(self, 'running', False))
        signal.signal(signal.SIGTERM, lambda s, f: setattr(self, 'running', False))
    
    @staticmethod
    def get_candle_boundary(timestamp_ms: int) -> int:
        return (timestamp_ms // CANDLE_INTERVAL_MS) * CANDLE_INTERVAL_MS
    
    async def init_exchange(self) -> bool:
        try:
            exchange_class = getattr(ccxtpro, EXCHANGE)
            config = {
                **EXCHANGE_CREDENTIALS,
                'enableRateLimit': True,
                'options': {'fetchTradesMethod': 'publicGetTrades', 'tradesLimit': 1000}
            }
            self.exchange = exchange_class(config)
            await self.exchange.load_markets()
            logger.info(f"Connected to {EXCHANGE}")
            return True
        except Exception as e:
            logger.error(f"Exchange init failed: {e}")
            return False
    
    async def websocket_handler(self, symbol: str):
        attempt = 0
        max_attempts = 10
        
        while self.running and attempt < max_attempts:
            try:
                while self.running:
                    trades = await asyncio.wait_for(self.exchange.watch_trades(symbol), timeout=30)
                    
                    if trades:
                        new_trades = []
                        for trade in trades:
                            trade_id = str(trade['id'])
                            if trade_id not in self.trade_id_sets[symbol]:
                                self.trade_id_sets[symbol].add(trade_id)
                                new_trades.append(RawTrade(
                                    id=trade_id,
                                    timestamp_ms=int(trade['timestamp']),
                                    price=float(trade['price']),
                                    amount=float(trade['amount']),
                                    symbol=symbol,
                                    side=trade.get('side', 'unknown')
                                ))
                        
                        if len(self.trade_id_sets[symbol]) > MAX_TRADE_IDS:
                            sorted_ids = sorted(self.trade_id_sets[symbol])
                            self.trade_id_sets[symbol] = set(sorted_ids[-MAX_TRADE_IDS//2:])
                        
                        if new_trades:
                            try:
                                await asyncio.wait_for(self.trade_queues[symbol].put(new_trades), timeout=1)
                                self.stats[f'{symbol}_trades'] += len(new_trades)
                            except asyncio.TimeoutError:
                                pass
                    
                    attempt = 0
                    
            except (asyncio.TimeoutError, Exception) as e:
                attempt += 1
                if attempt < max_attempts:
                    await asyncio.sleep(min(attempt * 2, 30))
    
    async def trade_processor(self, symbol: str):
        while self.running:
            try:
                trades = await asyncio.wait_for(self.trade_queues[symbol].get(), timeout=5)
                for trade in trades:
                    self.trade_buffers[symbol].append(trade)
                    boundary = self.get_candle_boundary(trade.timestamp_ms)
                    if boundary not in self.pending_candles[symbol]:
                        self.pending_candles[symbol][boundary] = []
                    self.pending_candles[symbol][boundary].append(trade)
                self.trade_queues[symbol].task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Trade processor error {symbol}: {e}")
                await asyncio.sleep(1)
    
    async def candle_generator(self, symbol: str):
        while self.running:
            try:
                current_time_ms = int(time.time() * 1000)
                current_boundary = self.get_candle_boundary(current_time_ms)
                
                completed_boundaries = [
                    boundary for boundary in self.pending_candles[symbol].keys()
                    if boundary < current_boundary - CANDLE_INTERVAL_MS
                ]
                
                for boundary in completed_boundaries:
                    trades_in_boundary = self.pending_candles[symbol][boundary]
                    if trades_in_boundary:
                        trades_in_boundary.sort(key=lambda t: t.timestamp_ms)
                        candle = self._construct_candle(boundary, trades_in_boundary, symbol)
                        if candle:
                            try:
                                await asyncio.wait_for(self.candle_queues[symbol].put(candle), timeout=1)
                                self.stats[f'{symbol}_candles'] += 1
                            except asyncio.TimeoutError:
                                pass
                    del self.pending_candles[symbol][boundary]
                
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Candle generator error {symbol}: {e}")
                await asyncio.sleep(5)
    
    def _construct_candle(self, boundary_ms: int, trades: List[RawTrade], symbol: str) -> Optional[Candle]:
        if not trades:
            return None
        
        prices = np.array([trade.price for trade in trades], dtype=np.float64)
        volumes = np.array([trade.amount for trade in trades], dtype=np.float64)
        
        return Candle(
            timestamp_ms=boundary_ms,
            open=float(prices[0]),
            high=float(np.max(prices)),
            low=float(np.min(prices)),
            close=float(prices[-1]),
            volume=float(np.sum(volumes)),
            trade_count=len(trades),
            symbol=symbol
        )
    
    async def database_writer(self, symbol: str):
        pending_candles = []
        
        while self.running:
            try:
                try:
                    candle = await asyncio.wait_for(self.candle_queues[symbol].get(), timeout=2)
                    pending_candles.append(candle)
                    self.candle_queues[symbol].task_done()
                except asyncio.TimeoutError:
                    pass
                
                if len(pending_candles) >= BATCH_SIZE or (pending_candles and time.time() % 5 < 1):
                    await self._write_candles(symbol, pending_candles)
                    pending_candles.clear()
                    
            except Exception as e:
                logger.error(f"Database writer error {symbol}: {e}")
                await asyncio.sleep(1)
        
        if pending_candles:
            await self._write_candles(symbol, pending_candles)
    
    async def _write_candles(self, symbol: str, candles: List[Candle]):
        if not candles:
            return
            
        async with self.db_semaphore:
            try:
                candle_data = [
                    [c.timestamp_ms, c.open, c.high, c.low, c.close, c.volume]
                    for c in candles
                ]
                
                await asyncio.get_event_loop().run_in_executor(
                    None, self.db.insert_candles, candle_data, symbol
                )
                
                self.stats[f'{symbol}_written'] += len(candles)
                logger.info(f"{symbol}: {len(candles)} candles written")
                
            except Exception as e:
                logger.error(f"Database write error {symbol}: {e}")
                for candle in candles:
                    try:
                        await asyncio.wait_for(self.candle_queues[symbol].put(candle), timeout=0.1)
                    except asyncio.TimeoutError:
                        break
    
    async def stats_monitor(self):
        while self.running:
            try:
                await asyncio.sleep(60)
                for symbol in SYMBOLS:
                    trades = self.stats[f'{symbol}_trades']
                    candles = self.stats[f'{symbol}_candles']
                    written = self.stats[f'{symbol}_written']
                    ratio = trades / max(candles, 1)
                    logger.info(f"{symbol}: T:{trades} C:{candles} W:{written} R:{ratio:.1f}")
            except Exception as e:
                logger.error(f"Stats monitor error: {e}")
    
    async def run(self):
        try:
            if not await self.init_exchange():
                return
            
            self.running = True
            logger.info("Starting 5s Data Collector")
            
            tasks = []
            for symbol in SYMBOLS:
                tasks.extend([
                    asyncio.create_task(self.websocket_handler(symbol)),
                    asyncio.create_task(self.trade_processor(symbol)),
                    asyncio.create_task(self.candle_generator(symbol)),
                    asyncio.create_task(self.database_writer(symbol)),
                ])
            
            tasks.append(asyncio.create_task(self.stats_monitor()))
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Collector error: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        logger.info("Shutting down collector...")
        self.running = False
        if self.exchange:
            await self.exchange.close()

async def main():
    collector = DataCollector()
    await collector.run()

if __name__ == "__main__":
    asyncio.run(main())