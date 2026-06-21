"""SQLite database for TradingView candles."""

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
                symbol TEXT, ts INTEGER, open REAL, high REAL, low REAL, close REAL, volume REAL,
                PRIMARY KEY (symbol, ts))''')
            c.execute('CREATE INDEX IF NOT EXISTS idx_candles_ts ON candles(ts)')
    
    def insert(self, symbol: str, ts: int, o: float, h: float, l: float, c: float, v: float, ignore: bool = False):
        with self.conn() as conn:
            sql = 'INSERT OR IGNORE INTO candles VALUES (?,?,?,?,?,?,?)' if ignore else 'INSERT OR REPLACE INTO candles VALUES (?,?,?,?,?,?,?)'
            conn.execute(sql, (symbol, ts, o, h, l, c, v))
            conn.commit()
    
    def get(self, symbol: str, limit: int = 100):
        with self.conn() as c:
            return c.execute('SELECT * FROM candles WHERE symbol=? ORDER BY ts DESC LIMIT ?', (symbol, limit)).fetchall()
    
    def prune(self, cutoff_ts: int):
        with self.conn() as c:
            c.execute('DELETE FROM candles WHERE ts < ?', (cutoff_ts,))
            c.commit()
    
    def count(self):
        with self.conn() as c:
            return c.execute('SELECT COUNT(*) FROM candles').fetchone()[0]

