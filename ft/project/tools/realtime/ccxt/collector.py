#!/usr/bin/env python3
"""CCXT 5-second candle collector."""

import asyncio
import logging
from datetime import datetime, timedelta
from client import CCXTClient
from database import CandleDatabase
from config import (
    EXCHANGE, EXCHANGE_CREDENTIALS, SYMBOLS, TIMEFRAME_MS,
    HISTORY_MINUTES, RETENTION_HOURS, PRUNE_INTERVAL, LOG_LEVEL, LOG_FILE
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger('ccxt')


async def main():
    db = CandleDatabase()
    client = CCXTClient(EXCHANGE, EXCHANGE_CREDENTIALS, SYMBOLS, TIMEFRAME_MS, HISTORY_MINUTES)
    last_prune = datetime.now()
    candle_count = 0
    
    log.info(f"Starting: {SYMBOLS} @ {TIMEFRAME_MS}ms")
    
    async for candle in client.stream():
        ts = int(candle.timestamp_ms / 1000)
        db.insert(
            candle.symbol, ts, 
            candle.open, candle.high, candle.low, candle.close, 
            candle.volume, candle.trade_count
        )
        candle_count += 1
        
        log.info(
            f"{candle.symbol} {candle.time.strftime('%H:%M:%S')} "
            f"O={candle.open:.2f} H={candle.high:.2f} L={candle.low:.2f} "
            f"C={candle.close:.2f} V={candle.volume:.2f} T={candle.trade_count}"
        )
        
        if (datetime.now() - last_prune).seconds > PRUNE_INTERVAL:
            cutoff = int((datetime.now() - timedelta(hours=RETENTION_HOURS)).timestamp())
            deleted = db.prune(cutoff)
            if deleted > 0:
                log.info(f"Pruned {deleted} old candles, total: {db.count()}")
            last_prune = datetime.now()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped")
