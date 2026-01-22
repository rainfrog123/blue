#!/usr/bin/env python3
"""View collected 5-second candles from CCXT collector."""

import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from tabulate import tabulate

from database import CandleDatabase
from config import SYMBOLS

class DataViewer:
    def __init__(self):
        self.db = CandleDatabase()
    
    def get_recent_candles(self, symbol: str, count: int = 20) -> pd.DataFrame:
        """Get recent candles for a symbol."""
        query = """
        SELECT timestamp, open, high, low, close, volume 
        FROM candles 
        WHERE symbol = ?
        ORDER BY timestamp DESC 
        LIMIT ?
        """
        
        try:
            conn = sqlite3.connect(self.db.db_path)
            df = pd.read_sql_query(query, conn, params=(symbol, count))
            conn.close()
            
            if not df.empty:
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='ms')
                df = df.sort_values('timestamp').reset_index(drop=True)
            
            return df
        except Exception as e:
            print(f"Error getting candles for {symbol}: {e}")
            return pd.DataFrame()
    
    def get_stats(self, symbol: str) -> dict:
        """Get statistics for a symbol."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM candles WHERE symbol = ?", (symbol,))
            total_candles = cursor.fetchone()[0]
            
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM candles WHERE symbol = ?", (symbol,))
            min_time, max_time = cursor.fetchone()
            
            hour_ago = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)
            cursor.execute("SELECT COUNT(*) FROM candles WHERE timestamp > ? AND symbol = ?", (hour_ago, symbol))
            recent_candles = cursor.fetchone()[0]
            
            cursor.execute("SELECT AVG(close), MIN(low), MAX(high), SUM(volume) FROM candles WHERE symbol = ?", (symbol,))
            avg_price, min_price, max_price, total_volume = cursor.fetchone()
            
            conn.close()
            
            return {
                'symbol': symbol,
                'total_candles': total_candles,
                'recent_candles': recent_candles,
                'min_time': datetime.fromtimestamp(min_time/1000) if min_time else None,
                'max_time': datetime.fromtimestamp(max_time/1000) if max_time else None,
                'avg_price': avg_price,
                'min_price': min_price,
                'max_price': max_price,
                'total_volume': total_volume
            }
        except Exception as e:
            print(f"Error getting stats for {symbol}: {e}")
            return {'symbol': symbol, 'error': str(e)}
    
    def show_overview(self):
        """Show overview of all symbols."""
        print("=== CCXT 5-Second Candle Database ===\n")
        
        stats_data = []
        for symbol in SYMBOLS:
            stats = self.get_stats(symbol)
            if 'error' not in stats:
                stats_data.append([
                    stats['symbol'],
                    f"{stats['total_candles']:,}",
                    f"{stats['recent_candles']:,}",
                    f"${stats['avg_price']:.2f}" if stats['avg_price'] else "N/A",
                    f"{stats['total_volume']:,.0f}" if stats['total_volume'] else "N/A",
                    stats['max_time'].strftime('%H:%M:%S') if stats['max_time'] else "N/A"
                ])
            else:
                stats_data.append([stats['symbol'], "ERROR", "N/A", "N/A", "N/A", "N/A"])
        
        headers = ['Symbol', 'Total Candles', 'Last Hour', 'Avg Price', 'Total Volume', 'Last Update']
        print(tabulate(stats_data, headers=headers, tablefmt='grid'))
        print()
    
    def show_recent_candles(self, symbol: str, count: int = 20):
        """Show recent candle data for a symbol."""
        print(f"=== Last {count} Candles for {symbol} ===\n")
        
        df = self.get_recent_candles(symbol, count)
        
        if df.empty:
            print(f"No data found for {symbol}")
            return
        
        display_data = []
        for _, row in df.iterrows():
            display_data.append([
                row['datetime'].strftime('%H:%M:%S'),
                f"${row['open']:.4f}",
                f"${row['high']:.4f}",
                f"${row['low']:.4f}",
                f"${row['close']:.4f}",
                f"{row['volume']:.2f}"
            ])
        
        headers = ['Time', 'Open', 'High', 'Low', 'Close', 'Volume']
        print(tabulate(display_data, headers=headers, tablefmt='grid'))
        
        print(f"\nSummary:")
        print(f"  Candles: {len(df)}")
        print(f"  Price Range: ${df['low'].min():.4f} - ${df['high'].max():.4f}")
        print(f"  Total Volume: {df['volume'].sum():.2f}")
        print()

def main():
    viewer = DataViewer()
    viewer.show_overview()
    
    for symbol in SYMBOLS:
        viewer.show_recent_candles(symbol, 20)
        print("-" * 80)

if __name__ == "__main__":
    main()

