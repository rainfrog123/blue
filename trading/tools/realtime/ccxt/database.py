"""SQLite database for CCXT candles."""

import sqlite3
from contextlib import contextmanager
from config import DB_PATH


class CandleDatabase:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._init()
    
    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c
        finally:
            c.close()
    
    def _init(self):
        with self.conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS candles (
                symbol TEXT, ts INTEGER, open REAL, high REAL, low REAL, 
                close REAL, volume REAL, trade_count INTEGER DEFAULT 0,
                PRIMARY KEY (symbol, ts))''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_candles_ts ON candles(ts)')
    
    def insert(self, symbol: str, ts: int, o: float, h: float, l: float, 
               c: float, v: float, trade_count: int = 0, ignore: bool = False):
        with self.conn() as conn:
            sql = ('INSERT OR IGNORE INTO candles VALUES (?,?,?,?,?,?,?,?)' 
                   if ignore else 
                   'INSERT OR REPLACE INTO candles VALUES (?,?,?,?,?,?,?,?)')
            conn.execute(sql, (symbol, ts, o, h, l, c, v, trade_count))
            conn.commit()
    
    def insert_batch(self, candles: list):
        """Insert multiple candles efficiently."""
        if not candles:
            return 0
        with self.conn() as conn:
            conn.executemany(
                'INSERT OR REPLACE INTO candles VALUES (?,?,?,?,?,?,?,?)',
                candles
            )
            conn.commit()
            return len(candles)
    
    def get(self, symbol: str, limit: int = 100):
        with self.conn() as c:
            return c.execute(
                'SELECT * FROM candles WHERE symbol=? ORDER BY ts DESC LIMIT ?',
                (symbol, limit)
            ).fetchall()
    
    def get_latest_ts(self, symbol: str) -> int:
        with self.conn() as c:
            row = c.execute(
                'SELECT MAX(ts) as max_ts FROM candles WHERE symbol=?',
                (symbol,)
            ).fetchone()
            return row['max_ts'] if row and row['max_ts'] else 0
    
    def prune(self, cutoff_ts: int) -> int:
        with self.conn() as c:
            cursor = c.execute('DELETE FROM candles WHERE ts < ?', (cutoff_ts,))
            c.commit()
            return cursor.rowcount
    
    def count(self, symbol: str = None) -> int:
        with self.conn() as c:
            if symbol:
                return c.execute(
                    'SELECT COUNT(*) FROM candles WHERE symbol=?', (symbol,)
                ).fetchone()[0]
            return c.execute('SELECT COUNT(*) FROM candles').fetchone()[0]
    
    def optimize(self):
        with self.conn() as c:
            c.execute('VACUUM')
            c.execute('ANALYZE')
