"""TradingView WebSocket client for OHLCV candles."""

import websocket
import json
import re
import random
import string
import threading
import asyncio
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, Optional

def gen_session(prefix: str = "cs") -> str:
    return f"{prefix}_{''.join(random.choices(string.ascii_letters + string.digits, k=12))}"

def wrap(msg: str) -> str:
    return f"~m~{len(msg)}~m~{msg}"

def unwrap(raw: str) -> list:
    msgs = []
    while raw:
        m = re.match(r"~m~(\d+)~m~", raw)
        if not m: break
        end = m.end() + int(m.group(1))
        msgs.append(raw[m.end():end])
        raw = raw[end:]
    return msgs

class TVClient:
    WS_URL = "wss://prodata.tradingview.com/socket.io/websocket"
    HEADERS = {"Origin": "https://www.tradingview.com"}
    
    def __init__(self, auth_token: str, symbols: list, timeframe: str = "5S", bars: int = 300):
        self.auth_token = auth_token
        self.symbols = symbols
        self.timeframe = timeframe
        self.bars = bars
        self.ws: Optional[websocket.WebSocketApp] = None
        self._queue: Optional[asyncio.Queue] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._current: Dict[str, list] = {}
        self._seen: set = set()
        self.chart_session = gen_session("cs")
    
    def _send(self, msg: dict):
        if self.ws:
            self.ws.send(wrap(json.dumps(msg)))
    
    def _on_open(self, ws):
        self._send({"m": "set_auth_token", "p": [self.auth_token]})
        self._send({"m": "set_locale", "p": ["en", "US"]})
        self._send({"m": "chart_create_session", "p": [self.chart_session, ""]})
        self._send({"m": "switch_timezone", "p": [self.chart_session, "Etc/UTC"]})
        
        for i, sym in enumerate(self.symbols):
            sym_id, series_id = f"sds_sym_{i+1}", f"sds_{i+1}"
            self._send({"m": "resolve_symbol", "p": [
                self.chart_session, sym_id,
                f'={{"adjustment":"splits","session":"regular","symbol":"{sym}"}}'
            ]})
            self._send({"m": "create_series", "p": [
                self.chart_session, series_id, f"s{i+1}", sym_id, self.timeframe, self.bars, ""
            ]})
    
    def _on_message(self, ws, message):
        for msg in unwrap(message):
            if not msg.strip(): continue
            if msg.startswith("~h~"):
                ws.send(wrap(msg))
                continue
            try:
                data = json.loads(msg)
                m, p = data.get("m"), data.get("p", [])
                if m in ("du", "timescale_update") and len(p) > 1:
                    self._handle_bars(p[1], m == "timescale_update")
            except: pass
    
    def _handle_bars(self, data: dict, is_history: bool = False):
        for key, val in data.items():
            if key.startswith("sds_") and "s" in val:
                for bar in val["s"]:
                    self._emit_bar(bar["v"], bar.get("i", 0) < 0 or is_history)
    
    def _emit_bar(self, ohlcv: list, is_history: bool = False):
        """Emit only CLOSED candles. Current forming candle is stored, emitted when next arrives."""
        ts = int(ohlcv[0])
        symbol = self.symbols[0]
        
        # When timestamp changes, the previous candle is closed - emit it
        prev = self._current.get(symbol)
        if prev and prev[0] != ts and prev[0] not in self._seen:
            self._seen.add(prev[0])
            self._put({
                "symbol": symbol,
                "time": datetime.utcfromtimestamp(prev[0]),
                "open": prev[1], "high": prev[2], "low": prev[3], 
                "close": prev[4], "volume": prev[5],
                "is_history": is_history
            })
        
        # Store current candle (will be emitted when next one arrives)
        self._current[symbol] = ohlcv
    
    def _put(self, data: dict):
        if self._queue and self._loop:
            asyncio.run_coroutine_threadsafe(self._queue.put(data), self._loop)
    
    def _run(self):
        self.ws = websocket.WebSocketApp(
            self.WS_URL, header=[f"{k}: {v}" for k, v in self.HEADERS.items()],
            on_open=self._on_open, on_message=self._on_message,
            on_error=lambda ws, e: None, on_close=lambda ws, s, m: None)
        self.ws.run_forever()
    
    async def stream(self) -> AsyncGenerator[Dict[str, Any], None]:
        self._queue = asyncio.Queue()
        self._loop = asyncio.get_event_loop()
        threading.Thread(target=self._run, daemon=True).start()
        try:
            while True:
                yield await self._queue.get()
        finally:
            if self.ws: self.ws.close()

