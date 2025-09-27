#!/usr/bin/env python3
"""Data viewer for 5-second candle database."""

import pandas as pd
from datetime import datetime, timedelta
from tabulate import tabulate
from database import Database
from config import SYMBOLS

class Viewer:
    """Candle data viewer."""
    
    def __init__(self):
        self.db = Database()
    
    def get_stats(self, symbol: str) -> dict:
        """Get comprehensive symbol statistics."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Single query for all stats
                hour_ago = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN timestamp > ? THEN 1 ELSE 0 END) as recent,
                        MIN(timestamp) as min_ts, MAX(timestamp) as max_ts,
                        AVG(close) as avg_price, MIN(low) as min_price, 
                        MAX(high) as max_price, SUM(volume) as total_vol
                    FROM candles WHERE symbol = ?
                """, (hour_ago, symbol))
                
                row = cursor.fetchone()
                return {
                    'symbol': symbol,
                    'total': row[0],
                    'recent': row[1], 
                    'last_time': datetime.fromtimestamp(row[3]/1000) if row[3] else None,
                    'avg_price': row[4],
                    'price_range': f"{row[5]:.4f}-{row[6]:.4f}" if row[5] else "N/A",
                    'total_volume': row[7]
                }
        except Exception as e:
            return {'symbol': symbol, 'error': str(e)}
    
    def get_recent_candles(self, symbol: str, count: int = 20) -> pd.DataFrame:
        """Get recent candles."""
        try:
            with self.db.get_connection() as conn:
                df = pd.read_sql_query("""
                    SELECT timestamp, open, high, low, close, volume 
                    FROM candles WHERE symbol = ? ORDER BY timestamp DESC LIMIT ?
                """, conn, params=(symbol, count))
                
                if not df.empty:
                    df['datetime'] = pd.to_datetime(df['timestamp'], unit='ms')
                    df = df.sort_values('timestamp').reset_index(drop=True)
                return df
        except Exception:
            return pd.DataFrame()
    
    def show_overview(self):
        """Show concise overview."""
        print(f"=== TradingView 5s Candle Database ===")
        print(f"Path: {self.db.db_path}\n")
        
        data = []
        for symbol in SYMBOLS:
            stats = self.get_stats(symbol)
            if 'error' not in stats:
                data.append([
                    stats['symbol'],
                    f"{stats['total']:,}" if stats['total'] else "0",
                    f"{stats['recent']:,}" if stats['recent'] else "0",
                    f"${stats['avg_price']:.2f}" if stats['avg_price'] else "N/A",
                    stats['price_range'],
                    stats['last_time'].strftime('%H:%M:%S') if stats['last_time'] else "N/A"
                ])
            else:
                data.append([stats['symbol'], "ERROR", "-", "-", "-", "-"])
        
        headers = ['Symbol', 'Total', 'Last 1h', 'Avg Price', 'Range', 'Last Update']
        print(tabulate(data, headers=headers, tablefmt='simple'))
        print()
    
    def show_recent(self, symbol: str, count: int = 10):
        """Show recent candles concisely."""
        df = self.get_recent_candles(symbol, count)
        if df.empty:
            print(f"No data for {symbol}\n")
            return
        
        # Show only essential columns
        data = [[
            row['datetime'].strftime('%H:%M:%S'),
            f"{row['close']:.4f}",
            f"{row['volume']:.1f}"
        ] for _, row in df.iterrows()]
        
        print(f"=== {symbol} - Last {count} Candles ===")
        print(tabulate(data, headers=['Time', 'Close', 'Vol'], tablefmt='simple'))
        print(f"Range: ${df['low'].min():.4f} - ${df['high'].max():.4f}, "
              f"Avg Vol: {df['volume'].mean():.1f}\n")

def main():
    viewer = Viewer()
    viewer.show_overview()
    for symbol in SYMBOLS:
        viewer.show_recent(symbol)

if __name__ == "__main__":
    main() 