#!/usr/bin/env python3
"""TradingView 5-second candle collector."""

import asyncio
import logging
from datetime import datetime, timedelta
from client import TVClient
from database import CandleDatabase
from config import AUTH_TOKEN, SYMBOLS, TIMEFRAME, INITIAL_BARS, RETENTION_HOURS, PRUNE_INTERVAL, LOG_LEVEL, LOG_FILE

logging.basicConfig(level=getattr(logging, LOG_LEVEL),
                   format='%(asctime)s %(levelname)s %(message)s',
                   handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
log = logging.getLogger('tv')

async def main():
    db = CandleDatabase()
    client = TVClient(AUTH_TOKEN, SYMBOLS, TIMEFRAME, INITIAL_BARS)
    last_prune = datetime.now()
    hist_count = 0
    hist_done = False
    
    log.info(f"Starting: {SYMBOLS} @ {TIMEFRAME}")
    
    async for data in client.stream():
        ts = int(data["time"].timestamp())
        is_hist = data.get("is_history", False)
        db.insert(data["symbol"], ts, data["open"], data["high"], data["low"], data["close"], data["volume"], ignore=is_hist)
        if is_hist:
            hist_count += 1
        else:
            if not hist_done:
                log.info(f"Loaded {hist_count} history bars, total in DB: {db.count()}")
                hist_done = True
            log.info(f"{data['symbol']} {data['time'].strftime('%H:%M:%S')} "
                    f"O={data['open']:.2f} H={data['high']:.2f} L={data['low']:.2f} C={data['close']:.2f} V={data['volume']:.2f}")
        
        if (datetime.now() - last_prune).seconds > PRUNE_INTERVAL:
            db.prune(int((datetime.now() - timedelta(hours=RETENTION_HOURS)).timestamp()))
            last_prune = datetime.now()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped")

