#!/usr/bin/env python3
"""
Database module for storing and retrieving market data.
Split into separate databases for trades and candles.
"""

import logging
import sqlite3
import pandas as pd
from datetime import datetime
import json
import os
from contextlib import contextmanager

from settings import TRADES_DB_PATH, CANDLES_DB_PATH, DATA_DIR

logger = logging.getLogger(__name__)

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

class MarketDatabase:
    """
    Database manager for market data with separate databases for trades and candles.
    """
    
    def __init__(self, trades_db_path=TRADES_DB_PATH, candles_db_path=CANDLES_DB_PATH):
        """Initialize the databases with the specified paths."""
        self.trades_db_path = trades_db_path
        self.candles_db_path = candles_db_path
        self._create_tables()
        logger.info(f"Initialized trades database at {trades_db_path}")
        logger.info(f"Initialized candles database at {candles_db_path}")
    
    @contextmanager
    def get_trades_connection(self):
        """Context manager for trades database connections."""
        conn = sqlite3.connect(self.trades_db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
        finally:
            conn.close()
    
    @contextmanager
    def get_candles_connection(self):
        """Context manager for candles database connections."""
        conn = sqlite3.connect(self.candles_db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
        finally:
            conn.close()
    
    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        # Create trades table
        with self.get_trades_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS trades (
                id TEXT PRIMARY KEY,
                symbol TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                datetime TEXT NOT NULL,
                price REAL NOT NULL,
                amount REAL NOT NULL,
                side TEXT NOT NULL,
                info TEXT,
                UNIQUE(id, symbol)
            )
            ''')
            
            # Create index on timestamp and symbol for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_trades_ts_symbol ON trades (timestamp, symbol)')
            
            conn.commit()
        
        # Create candles table
        with self.get_candles_connection() as conn:
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
            
            # Create index on timestamp and symbol for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_candles_ts_symbol ON candles (timestamp, symbol)')
            
            conn.commit()
    
    def insert_trades(self, trades, symbol):
        """Insert multiple trades for a symbol into the trades database."""
        if not trades:
            return 0
        
        with self.get_trades_connection() as conn:
            cursor = conn.cursor()
            inserted = 0
            
            for trade in trades:
                try:
                    # Convert trade info to JSON
                    info_json = json.dumps(trade['info']) if 'info' in trade else None
                    
                    cursor.execute('''
                    INSERT OR IGNORE INTO trades 
                    (id, symbol, timestamp, datetime, price, amount, side, info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        str(trade['id']),
                        symbol,
                        int(trade['timestamp']),
                        trade['datetime'],
                        float(trade['price']),
                        float(trade['amount']),
                        trade['side'],
                        info_json
                    ))
                    if cursor.rowcount > 0:
                        inserted += 1
                except Exception as e:
                    logger.error(f"Error inserting trade {trade}: {e}")
            
            conn.commit()
            if inserted > 0:
                logger.debug(f"Inserted {inserted} new trades for {symbol}")
            return inserted
    
    def insert_candle(self, candle, symbol):
        """Insert a 5s candle for a symbol into the candles database."""
        with self.get_candles_connection() as conn:
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
                    float(candle[1]),  # open
                    float(candle[2]),  # high
                    float(candle[3]),  # low
                    float(candle[4]),  # close
                    float(candle[5])   # volume
                ))
                
                conn.commit()
                return cursor.rowcount
            except Exception as e:
                logger.error(f"Error inserting candle {candle} for {symbol}: {e}")
                return 0
    
    def insert_candles(self, candles, symbol):
        """Insert multiple 5s candles for a symbol into the candles database."""
        if not candles:
            return 0
        
        with self.get_candles_connection() as conn:
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
                        float(candle[1]),  # open
                        float(candle[2]),  # high
                        float(candle[3]),  # low
                        float(candle[4]),  # close
                        float(candle[5])   # volume
                    ))
                    inserted += cursor.rowcount
                except Exception as e:
                    logger.error(f"Error inserting candle {candle} for {symbol}: {e}")
            
            conn.commit()
            if inserted > 0:
                logger.debug(f"Inserted {inserted} candles for {symbol}")
            return inserted
    
    def get_latest_trade_timestamp(self, symbol):
        """Get the timestamp of the latest trade for a symbol."""
        with self.get_trades_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(timestamp) as max_ts FROM trades WHERE symbol = ?', (symbol,))
            result = cursor.fetchone()
            return result['max_ts'] if result and result['max_ts'] else 0
    
    def get_latest_candle_timestamp(self, symbol):
        """Get the timestamp of the latest candle for a symbol."""
        with self.get_candles_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(timestamp) as max_ts FROM candles WHERE symbol = ?', (symbol,))
            result = cursor.fetchone()
            return result['max_ts'] if result and result['max_ts'] else 0
    
    def get_trades(self, symbol, start_time=None, end_time=None, limit=None):
        """Get trades for a symbol with optional time filtering."""
        query = 'SELECT * FROM trades WHERE symbol = ?'
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
        
        with self.get_trades_connection() as conn:
            return pd.read_sql_query(query, conn, params=params)
    
    def get_candles(self, symbol, start_time=None, end_time=None, limit=None):
        """Get 5s candles for a symbol with optional time filtering."""
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
        
        with self.get_candles_connection() as conn:
            return pd.read_sql_query(query, conn, params=params)
    
    def prune_old_data(self, symbol, data_type, cutoff_timestamp):
        """
        Remove data older than the specified cutoff timestamp.
        
        Args:
            symbol: The trading pair symbol.
            data_type: Either 'trades' or 'candles'.
            cutoff_timestamp: Remove data older than this timestamp (in milliseconds).
            
        Returns:
            Number of records deleted.
        """
        try:
            if data_type == "trades":
                with self.get_trades_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'DELETE FROM trades WHERE symbol = ? AND timestamp < ?',
                        (symbol, cutoff_timestamp)
                    )
                    deleted = cursor.rowcount
                    conn.commit()
                    return deleted
            elif data_type == "candles":
                with self.get_candles_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'DELETE FROM candles WHERE symbol = ? AND timestamp < ?',
                        (symbol, cutoff_timestamp)
                    )
                    deleted = cursor.rowcount
                    conn.commit()
                    return deleted
            else:
                logger.error(f"Invalid data type for pruning: {data_type}")
                return 0
        except Exception as e:
            logger.error(f"Error pruning old {data_type} for {symbol}: {e}")
            return 0
    
    def prune_old_trades(self, symbol, max_trades):
        """Remove oldest trades beyond the maximum count to keep database size in check."""
        with self.get_trades_connection() as conn:
            cursor = conn.cursor()
            
            # Get count of trades for the symbol
            cursor.execute('SELECT COUNT(*) as count FROM trades WHERE symbol = ?', (symbol,))
            result = cursor.fetchone()
            total_trades = result['count'] if result else 0
            
            if total_trades > max_trades:
                # Find the timestamp cutoff for deletion
                excess = total_trades - max_trades
                cursor.execute(
                    'SELECT timestamp FROM trades WHERE symbol = ? ORDER BY timestamp ASC LIMIT 1 OFFSET ?',
                    (symbol, excess)
                )
                result = cursor.fetchone()
                if result:
                    cutoff_ts = result['timestamp']
                    
                    # Delete trades older than the cutoff
                    cursor.execute(
                        'DELETE FROM trades WHERE symbol = ? AND timestamp < ?',
                        (symbol, cutoff_ts)
                    )
                    deleted = cursor.rowcount
                    conn.commit()
                    logger.info(f"Pruned {deleted} old trades for {symbol}")
                    return deleted
            
            return 0

    def optimize_database(self):
        """Perform optimization tasks on both databases."""
        # Optimize trades database
        try:
            with self.get_trades_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('VACUUM')
                cursor.execute('ANALYZE')
                
                # Get database statistics
                cursor.execute("SELECT COUNT(*) as count FROM trades")
                trades_count = cursor.fetchone()['count']
            
            # Optimize candles database
            with self.get_candles_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('VACUUM')
                cursor.execute('ANALYZE')
                
                # Get database statistics
                cursor.execute("SELECT COUNT(*) as count FROM candles")
                candles_count = cursor.fetchone()['count']
            
            logger.info(f"Databases optimized. Current stats: {trades_count} trades, {candles_count} candles")
            return True
        except Exception as e:
            logger.error(f"Error optimizing databases: {e}")
            return False
    
    def close(self):
        """Close any remaining database resources."""
        # SQLite connections are automatically closed by the context manager
        # This method is here for compatibility and future extensions
        pass 