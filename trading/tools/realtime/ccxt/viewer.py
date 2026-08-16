#!/usr/bin/env python3
"""View collected 5-second candles from CCXT collector."""

from datetime import datetime, timedelta
from tabulate import tabulate
from database import CandleDatabase
from config import SYMBOLS, TIMEFRAME_MS


class DataViewer:
    def __init__(self):
        self.db = CandleDatabase()
        self.interval = TIMEFRAME_MS // 1000
    
    def get_recent_candles(self, symbol: str, count: int = 20) -> list:
        return self.db.get(symbol, count)
    
    def get_stats(self, symbol: str) -> dict:
        try:
            with self.db.conn() as c:
                total = c.execute(
                    "SELECT COUNT(*) FROM candles WHERE symbol=?", (symbol,)
                ).fetchone()[0]
                
                row = c.execute(
                    "SELECT MIN(ts), MAX(ts) FROM candles WHERE symbol=?", (symbol,)
                ).fetchone()
                min_ts, max_ts = row[0], row[1]
                
                hour_ago = int((datetime.now() - timedelta(hours=1)).timestamp())
                recent = c.execute(
                    "SELECT COUNT(*) FROM candles WHERE ts>? AND symbol=?",
                    (hour_ago, symbol)
                ).fetchone()[0]
                
                agg = c.execute(
                    "SELECT AVG(close), MIN(low), MAX(high), SUM(volume) "
                    "FROM candles WHERE symbol=?", (symbol,)
                ).fetchone()
                
                # Calculate expected vs actual candles
                expected = 0
                gaps = []
                if min_ts and max_ts:
                    expected = (max_ts - min_ts) // self.interval + 1
                    
                    # Find gaps
                    all_ts = c.execute(
                        "SELECT ts FROM candles WHERE symbol=? ORDER BY ts",
                        (symbol,)
                    ).fetchall()
                    
                    for i in range(1, len(all_ts)):
                        diff = all_ts[i][0] - all_ts[i-1][0]
                        if diff > self.interval:
                            gaps.append({
                                'from': datetime.fromtimestamp(all_ts[i-1][0]),
                                'to': datetime.fromtimestamp(all_ts[i][0]),
                                'missed': diff // self.interval - 1
                            })
                
                return {
                    'symbol': symbol,
                    'total': total,
                    'expected': expected,
                    'missed': expected - total,
                    'gaps': gaps,
                    'recent': recent,
                    'min_ts': datetime.fromtimestamp(min_ts) if min_ts else None,
                    'max_ts': datetime.fromtimestamp(max_ts) if max_ts else None,
                    'avg_price': agg[0],
                    'min_price': agg[1],
                    'max_price': agg[2],
                    'total_volume': agg[3]
                }
        except Exception as e:
            return {'symbol': symbol, 'error': str(e)}
    
    def show_overview(self):
        print("=== CCXT 5-Second Candle Database ===\n")
        
        for symbol in SYMBOLS:
            s = self.get_stats(symbol)
            if 'error' in s:
                print(f"{symbol}: ERROR - {s['error']}\n")
                continue
            
            time_range = "N/A"
            if s['min_ts'] and s['max_ts']:
                time_range = f"{s['min_ts'].strftime('%H:%M:%S')} - {s['max_ts'].strftime('%H:%M:%S')}"
            
            print(f"{symbol}")
            print(f"  Time Range: {time_range}")
            print(f"  Candles: {s['total']:,} / {s['expected']:,} expected ({s['missed']} missed)")
            print(f"  Last Hour: {s['recent']:,}")
            print(f"  Avg Price: ${s['avg_price']:.2f}" if s['avg_price'] else "  Avg Price: N/A")
            print(f"  Volume: {s['total_volume']:,.0f}" if s['total_volume'] else "  Volume: N/A")
            
            if s['gaps']:
                print(f"\n  Gaps ({len(s['gaps'])}):")
                for g in s['gaps'][-5:]:  # Show last 5 gaps
                    print(f"    {g['from'].strftime('%H:%M:%S')} - {g['to'].strftime('%H:%M:%S')} ({g['missed']} missed)")
                if len(s['gaps']) > 5:
                    print(f"    ... and {len(s['gaps']) - 5} more gaps")
            
            print()
    
    def show_recent(self, symbol: str, count: int = 15):
        print(f"=== Last {count} Candles for {symbol} ===\n")
        
        candles = self.get_recent_candles(symbol, count)
        if not candles:
            print(f"No data for {symbol}")
            return
        
        rows = []
        for c in reversed(candles):
            dt = datetime.fromtimestamp(c['ts'])
            rows.append([
                dt.strftime('%H:%M:%S'),
                f"${c['open']:.4f}",
                f"${c['high']:.4f}",
                f"${c['low']:.4f}",
                f"${c['close']:.4f}",
                f"{c['volume']:.2f}"
            ])
        
        headers = ['Time', 'Open', 'High', 'Low', 'Close', 'Volume']
        print(tabulate(rows, headers=headers, tablefmt='grid'))
        print()


def main():
    viewer = DataViewer()
    viewer.show_overview()
    
    for symbol in SYMBOLS:
        viewer.show_recent(symbol)
        print("-" * 60)


if __name__ == "__main__":
    main()
