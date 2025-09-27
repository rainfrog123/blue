#!/usr/bin/env python3
"""TradingView 5-second candle collector."""

import asyncio
import logging
from datetime import datetime, timedelta
from client import TradingViewClient
from database import Database
from config import SYMBOLS, LOG_LEVEL, LOG_FILE, RETENTION_HOURS, PRUNE_INTERVAL_MINUTES

# Setup logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL), 
                   format='%(asctime)s - %(levelname)s - %(message)s',
                   handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger('collector')

class Collector:
    """Manages candle collection and data retention."""
    
    def __init__(self):
        self.db = Database()
        self.client = TradingViewClient()
        self.last_prune = datetime.now()
        
    async def prune_if_needed(self, symbol):
        """Prune old data if interval elapsed."""
        if (datetime.now() - self.last_prune).seconds < PRUNE_INTERVAL_MINUTES * 60:
            return
            
        cutoff_ms = int((datetime.now() - timedelta(hours=RETENTION_HOURS)).timestamp() * 1000)
        deleted = self.db.prune_old_data(symbol, cutoff_ms)
        
        if deleted > 0:
            logger.info(f"Pruned {deleted} candles older than {RETENTION_HOURS}h")
        self.db.optimize_database()
        self.last_prune = datetime.now()
    
    async def collect(self):
        """Main collection loop."""
        symbol = SYMBOLS[0]
        logger.info(f"Starting collection for {symbol} (retention: {RETENTION_HOURS}h)")
        
        async for candle in self.client.candle_generator():
            # Convert to DB format
            ts_ms = int(candle["time"].timestamp() * 1000)
            db_row = [ts_ms, candle["open"], candle["high"], candle["low"], 
                     candle["close"], candle["volume"]]
            
            # Save and log
            self.db.insert_candles(db_row, symbol)
            logger.info(f"{candle['time'].strftime('%H:%M:%S')} "
                       f"OHLCV: {candle['open']:.4f}/{candle['high']:.4f}/"
                       f"{candle['low']:.4f}/{candle['close']:.4f}/{candle['volume']:.2f}")
            
            await self.prune_if_needed(symbol)

async def main():
    collector = Collector()
    try:
        await collector.collect()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
    finally:
        logger.info("Collector terminated")

if __name__ == "__main__":
    asyncio.run(main())
