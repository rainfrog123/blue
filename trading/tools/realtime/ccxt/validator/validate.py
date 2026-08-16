#!/usr/bin/env python3
"""Validate 5s candles against 1m exchange data."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

import ccxt.pro as ccxtpro
from config import EXCHANGE, EXCHANGE_CREDENTIALS, SYMBOLS
from database import CandleDatabase


async def fetch_1m(symbol: str, limit: int = 10):
    """Fetch last N 1-minute candles from exchange."""
    exchange = getattr(ccxtpro, EXCHANGE)(EXCHANGE_CREDENTIALS)
    try:
        await exchange.load_markets()
        ohlcv = await exchange.fetch_ohlcv(symbol, '1m', limit=limit)
        return [(int(r[0]/1000), r[1], r[2], r[3], r[4], r[5]) for r in ohlcv]
    finally:
        await exchange.close()


def aggregate_5s(db: CandleDatabase, symbol: str, ts_start: int, ts_end: int):
    """Aggregate 5s candles to 1m for a time range."""
    with db.conn() as c:
        rows = c.execute(
            'SELECT * FROM candles WHERE symbol=? AND ts>=? AND ts<? ORDER BY ts',
            (symbol, ts_start, ts_end)
        ).fetchall()
    
    if not rows:
        return None
    
    # Filter out corrupted candles (price=0)
    valid = [r for r in rows if r['open'] > 0 and r['low'] > 0]
    if not valid:
        return None
    
    return {
        'o': valid[0]['open'],
        'h': max(r['high'] for r in valid),
        'l': min(r['low'] for r in valid),
        'c': valid[-1]['close'],
        'v': sum(r['volume'] for r in valid),
        'n': len(valid)
    }


def pct_diff(a, b):
    if a == 0 and b == 0:
        return 0
    if a == 0 or b == 0:
        return 100
    return abs(a - b) / max(abs(a), abs(b)) * 100


async def validate(symbol: str, minutes: int = 10):
    """Validate last N minutes."""
    print(f"\n{'='*60}")
    print(f"Validating {symbol} - last {minutes} minutes")
    print(f"{'='*60}")
    
    candles_1m = await fetch_1m(symbol, minutes)
    db = CandleDatabase()
    
    ok = 0
    total = 0
    
    for ts, o, h, l, c, v in candles_1m[:-1]:  # skip last (incomplete)
        agg = aggregate_5s(db, symbol, ts, ts + 60)
        time_str = datetime.fromtimestamp(ts, timezone.utc).strftime('%H:%M')
        
        if not agg:
            print(f"  {time_str} - NO 5s DATA")
            continue
        
        total += 1
        d_o = pct_diff(o, agg['o'])
        d_h = pct_diff(h, agg['h'])
        d_l = pct_diff(l, agg['l'])
        d_c = pct_diff(c, agg['c'])
        d_v = pct_diff(v, agg['v'])
        
        price_ok = max(d_o, d_h, d_l, d_c) < 0.01
        vol_ok = d_v < 5
        
        if price_ok and vol_ok:
            ok += 1
            print(f"  {time_str} OK  (5s_count={agg['n']:2d})")
        else:
            print(f"  {time_str} MISMATCH (5s_count={agg['n']:2d})")
            print(f"    1m: O={o:.2f} H={h:.2f} L={l:.2f} C={c:.2f} V={v:.4f}")
            print(f"    5s: O={agg['o']:.2f} H={agg['h']:.2f} L={agg['l']:.2f} C={agg['c']:.2f} V={agg['v']:.4f}")
            print(f"    diff: O={d_o:.3f}% H={d_h:.3f}% L={d_l:.3f}% C={d_c:.3f}% V={d_v:.1f}%")
    
    if total > 0:
        print(f"\nResult: {ok}/{total} ({ok/total*100:.0f}%) validated OK")
    else:
        print("\nNo data to validate - run collector first")


async def main():
    for symbol in SYMBOLS:
        await validate(symbol, minutes=10)


if __name__ == "__main__":
    asyncio.run(main())
