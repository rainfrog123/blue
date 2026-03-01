#!/usr/bin/env python3
"""View collected 5-second candles from CCXT collector."""

from datetime import datetime, timedelta
from tabulate import tabulate
from database import CandleDatabase
from config import SYMBOLS


class DataViewer:
    def __init__(self):
        self.db = CandleDatabase()
    
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
                
                return {
                    'symbol': symbol,
                    'total': total,
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
        
        rows = []
        for symbol in SYMBOLS:
            s = self.get_stats(symbol)
            if 'error' not in s:
                rows.append([
                    s['symbol'],
                    f"{s['total']:,}",
                    f"{s['recent']:,}",
                    f"${s['avg_price']:.2f}" if s['avg_price'] else "N/A",
                    f"{s['total_volume']:,.0f}" if s['total_volume'] else "N/A",
                    s['max_ts'].strftime('%H:%M:%S') if s['max_ts'] else "N/A"
                ])
            else:
                rows.append([s['symbol'], "ERROR", "N/A", "N/A", "N/A", "N/A"])
        
        headers = ['Symbol', 'Total', 'Last Hour', 'Avg Price', 'Volume', 'Last Update']
        print(tabulate(rows, headers=headers, tablefmt='grid'))
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
