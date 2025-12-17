#!/usr/bin/env python3
"""View collected candles."""

from datetime import datetime
from database import Database
from config import SYMBOLS

def main():
    db = Database()
    print(f"=== TV Collector ({db.count():,} candles) ===\n")
    
    for sym in SYMBOLS:
        candles = db.get(sym, 15)
        if candles:
            print(f"--- {sym} (last 15) ---")
            for c in reversed(candles):
                t = datetime.fromtimestamp(c['ts']).strftime('%H:%M:%S')
                print(f"{t} O={c['open']:.2f} H={c['high']:.2f} L={c['low']:.2f} C={c['close']:.2f} V={c['volume']:.1f}")
            print()

if __name__ == "__main__":
    main()
