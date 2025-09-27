"""TradingView WebSocket client for 5-second candles."""

import websocket
import json
import time
import threading
import asyncio
import re
from datetime import datetime
from typing import AsyncGenerator, Dict, Any, Optional
from config import AUTH_TOKEN, WS_URL, SESSION_ID, SYMBOLS

HEADERS = {
    "Origin": "https://www.tradingview.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

def get_payloads(session_id, symbol, auth_token):
    """Generate WebSocket payloads."""
    return {
        'auth': json.dumps({"m": "set_auth_token", "p": [auth_token]}),
        'session': json.dumps({"m": "chart_create_session", "p": [session_id, ""]}),
        'resolve': json.dumps({
            "m": "resolve_symbol",
            "p": [session_id, "sds_sym_1", 
                 f'={{"adjustment":"splits","currency-id":"XTVCUSDT","session":"regular","symbol":"{symbol}"}}']
        }),
        'series': json.dumps({
            "m": "create_series",
            "p": [session_id, "sds_1", "s1", "sds_sym_1", "5S", 300, ""]
        })
    }

def wrap_message(msg: str) -> str:
    return f"~m~{len(msg)}~m~{msg}"

def split_tradingview_messages(raw):
    messages = []
    while raw:
        match = re.match(r"~m~(\d+)~m~", raw)
        if not match:
            break
        length = int(match.group(1))
        start = match.end()
        end = start + length
        json_part = raw[start:end]
        messages.append(json_part)
        raw = raw[end:]
    return messages

class TradingViewClient:
    """TradingView WebSocket client for 5s candles."""
    
    def __init__(self):
        self.ws = None
        self._queue: Optional[asyncio.Queue] = None
        self._loop = None
        self._current_candle = None
        self.payloads = get_payloads(SESSION_ID, SYMBOLS[0], AUTH_TOKEN)

    def _on_open(self, ws):
        """Initialize WebSocket connection sequence."""
        def send_sequence():
            for delay, payload in [(0, 'auth'), (1, 'session'), (2, 'resolve'), (3, 'series')]:
                time.sleep(delay)
                ws.send(wrap_message(self.payloads[payload]))
        threading.Thread(target=send_sequence, daemon=True).start()

    def _on_message(self, ws, message):
        """Process incoming WebSocket messages."""
        for msg in split_tradingview_messages(message):
            try:
                if not msg.strip():
                    continue
                    
                # Handle heartbeat
                if re.match(r"^~h~\d+$", msg):
                    ws.send(f"~m~{len(msg)}~m~{msg}")
                    continue
                
                # Process candle data
                data = json.loads(msg)
                if data.get("m") == "du" and len(data.get("p", [])) > 1:
                    self._process_candle_data(data["p"][1])
            except Exception:
                pass

    def _process_candle_data(self, data):
        """Extract and queue candle data."""
        sds_data = data.get("sds_1", {}).get("s", [])
        for bar in sds_data:
            ohlcv = bar["v"]
            candle_time = int(ohlcv[0])
            
            # Emit previous candle when new one arrives
            if self._current_candle and candle_time != self._current_candle[0]:
                candle = {
                    "time": datetime.utcfromtimestamp(self._current_candle[0]),
                    "open": self._current_candle[1],
                    "high": self._current_candle[2],
                    "low": self._current_candle[3],
                    "close": self._current_candle[4],
                    "volume": self._current_candle[5]
                }
                if self._queue:
                    asyncio.run_coroutine_threadsafe(self._queue.put(candle), self._loop)
            
            self._current_candle = ohlcv

    def _run_ws(self):
        """Run WebSocket connection."""
        self.ws = websocket.WebSocketApp(
            WS_URL,
            header=[f"{k}: {v}" for k, v in HEADERS.items()],
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=lambda ws, error: None,
            on_close=lambda ws, status, msg: None
        )
        self.ws.run_forever()

    async def candle_generator(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Async generator yielding 5s candles."""
        self._queue = asyncio.Queue()
        self._loop = asyncio.get_event_loop()
        threading.Thread(target=self._run_ws, daemon=True).start()
        
        try:
            while True:
                yield await self._queue.get()
        finally:
            if self.ws:
                self.ws.close() 