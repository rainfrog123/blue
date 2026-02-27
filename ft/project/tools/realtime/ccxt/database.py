#!/usr/bin/env python3
"""
SQLite database module for storing 5-second OHLCV candles.
"""

import logging
import sqlite3
import pandas as pd
from datetime import datetime
from contextlib import contextmanager

from config import CANDLES_DB_PATH, DATA_DIR
import os

logger = logging.getLogger(__name__)

os.makedirs(DATA_DIR, exist_ok=True)

class CandleDatabase:
    """Database manager for 5-second OHLCV candles."""
    
    def __init__(self, db_path=CANDLES_DB_PATH):
        self.db_path = db_path
        self._create_tables()
        logger.info(f"Initialized candles database at {db_path}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
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
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_candles_ts_symbol ON candles (timestamp, symbol)')
            conn.commit()
    
    def insert_candle(self, candle, symbol):
        """Insert a single 5s candle."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                timestamp = int(candle[0])
                datetime_str = pd.to_datetime(timestamp, unit='ms').strftime('%Y-%m-%d %H:%M:%S.%f')
                
                cursor.execute('''
                INSERT OR REPLACE INTO candles 
                (symbol, timestamp, datetime, open, high, low, close, volume)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    symbol,
                    timestamp,
                    datetime_str,
                    float(candle[1]),
                    float(candle[2]),
                    float(candle[3]),
                    float(candle[4]),
                    float(candle[5])
                ))
                
                conn.commit()
                return cursor.rowcount
            except Exception as e:
                logger.error(f"Error inserting candle {candle} for {symbol}: {e}")
                return 0
    
    def insert_candles(self, candles, symbol):
        """Insert multiple 5s candles."""
        if not candles:
            return 0
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            inserted = 0
            
            for candle in candles:
                try:
                    timestamp = int(candle[0])
                    datetime_str = pd.to_datetime(timestamp, unit='ms').strftime('%Y-%m-%d %H:%M:%S.%f')
                    
                    cursor.execute('''
                    INSERT OR REPLACE INTO candles 
                    (symbol, timestamp, datetime, open, high, low, close, volume)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        symbol,
                        timestamp,
                        datetime_str,
                        float(candle[1]),
                        float(candle[2]),
                        float(candle[3]),
                        float(candle[4]),
                        float(candle[5])
                    ))
                    inserted += cursor.rowcount
                except Exception as e:
                    logger.error(f"Error inserting candle {candle} for {symbol}: {e}")
            
            conn.commit()
            if inserted > 0:
                logger.debug(f"Inserted {inserted} candles for {symbol}")
            return inserted
    
    def get_latest_timestamp(self, symbol):
        """Get the timestamp of the latest candle for a symbol."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(timestamp) as max_ts FROM candles WHERE symbol = ?', (symbol,))
            result = cursor.fetchone()
            return result['max_ts'] if result and result['max_ts'] else 0
    
    def get_candles(self, symbol, start_time=None, end_time=None, limit=None):
        """Get candles for a symbol with optional time filtering."""
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
    
    def prune(self, symbol, cutoff_timestamp):
        """Remove candles older than the cutoff timestamp."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM candles WHERE symbol = ? AND timestamp < ?',
                    (symbol, cutoff_timestamp)
                )
                deleted = cursor.rowcount
                conn.commit()
                return deleted
        except Exception as e:
            logger.error(f"Error pruning candles for {symbol}: {e}")
            return 0
    
    def optimize(self):
        """Optimize the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('VACUUM')
                cursor.execute('ANALYZE')
                
                cursor.execute("SELECT COUNT(*) as count FROM candles")
                candles_count = cursor.fetchone()['count']
            
            logger.info(f"Database optimized. Total candles: {candles_count}")
            return True
        except Exception as e:
            logger.error(f"Error optimizing database: {e}")
            return False
    
    def count(self, symbol=None):
        """Get count of candles, optionally filtered by symbol."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if symbol:
                cursor.execute('SELECT COUNT(*) FROM candles WHERE symbol = ?', (symbol,))
            else:
                cursor.execute('SELECT COUNT(*) FROM candles')
            return cursor.fetchone()[0]

