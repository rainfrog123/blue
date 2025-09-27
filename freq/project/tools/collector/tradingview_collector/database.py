#!/usr/bin/env python3
"""Database module for TradingView 5s candle storage."""

import logging
import sqlite3
import pandas as pd
from datetime import datetime
import os
from contextlib import contextmanager
from config import DB_PATH, DATA_DIR

logger = logging.getLogger(__name__)
os.makedirs(DATA_DIR, exist_ok=True)

class Database:
    """Lightweight database manager for 5-second candles."""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._create_tables()
        logger.info(f"Database initialized: {self.db_path}")

    @contextmanager
    def get_connection(self):
        """Database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _create_tables(self):
        """Create candles table and index."""
        with self.get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS candles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    datetime TEXT NOT NULL,
                    open REAL NOT NULL,
                    high REAL NOT NULL,
                    low REAL NOT NULL,
                    close REAL NOT NULL,
                    volume REAL NOT NULL,
                    UNIQUE(timestamp, symbol)
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_candles_ts_symbol ON candles (timestamp, symbol)')
    
    def _format_candle_data(self, candle, symbol):
        """Convert candle array to database format."""
        timestamp = int(candle[0])
        datetime_str = pd.to_datetime(timestamp, unit='ms').strftime('%Y-%m-%d %H:%M:%S.%f')
        return (symbol, timestamp, datetime_str, *[float(x) for x in candle[1:6]])
    
    def insert_candles(self, candles, symbol):
        """Insert candles (single candle or list)."""
        if not candles:
            return 0
        
        # Handle single candle case
        if not isinstance(candles[0], (list, tuple)):
            candles = [candles]
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            inserted = 0
            for candle in candles:
                try:
                    data = self._format_candle_data(candle, symbol)
                    cursor.execute('''
                        INSERT OR REPLACE INTO candles 
                        (symbol, timestamp, datetime, open, high, low, close, volume)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', data)
                    inserted += cursor.rowcount
                except Exception as e:
                    logger.error(f"Error inserting candle for {symbol}: {e}")
            conn.commit()
            return inserted
    
    def get_latest_timestamp(self, symbol):
        """Get latest candle timestamp."""
        with self.get_connection() as conn:
            result = conn.execute('SELECT MAX(timestamp) FROM candles WHERE symbol = ?', (symbol,)).fetchone()
            return result[0] or 0
    
    def get_candles(self, symbol, start_time=None, end_time=None, limit=None):
        """Get candles with optional filtering."""
        query = 'SELECT * FROM candles WHERE symbol = ?'
        params = [symbol]
        if start_time:
            query += ' AND timestamp >= ?'
            params.append(start_time)
        if end_time:
            query += ' AND timestamp <= ?'
            params.append(end_time)
        query += ' ORDER BY timestamp ASC'
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        with self.get_connection() as conn:
            return pd.read_sql_query(query, conn, params=params)
    
    def prune_old_data(self, symbol, cutoff_timestamp):
        """Remove old candle data, return deleted count."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('DELETE FROM candles WHERE symbol = ? AND timestamp < ?',
                                    (symbol, cutoff_timestamp))
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Pruning error for {symbol}: {e}")
            return 0
    
    def optimize_database(self):
        """Optimize database and return stats."""
        try:
            with self.get_connection() as conn:
                conn.execute('VACUUM')
                conn.execute('ANALYZE')
                count = conn.execute("SELECT COUNT(*) FROM candles").fetchone()[0]
            logger.info(f"Database optimized: {count:,} candles")
            return True
        except Exception as e:
            logger.error(f"Optimization error: {e}")
            return False 