#!/usr/bin/env python3
"""Configuration for TradingView 5s candle collector."""

import os

# Directories
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Database
DB_PATH = os.path.join(DATA_DIR, "candles.db")

# Collection settings
SYMBOLS = ["BINANCE:ETHUSDT.P"]
RETENTION_HOURS = 3
PRUNE_INTERVAL_MINUTES = 10

# TradingView WebSocket
AUTH_TOKEN = "eyJhbGciOiJSUzUxMiIsImtpZCI6IkdaeFUiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMTYwMzg4MjcsImV4cCI6MTc1ODk1NjQyOCwiaWF0IjoxNzU4OTQyMDI4LCJwbGFuIjoicHJvX3ByZW1pdW1fdHJpYWwiLCJwcm9zdGF0dXMiOiJub25fcHJvIiwiZXh0X2hvdXJzIjoxLCJwZXJtIjoiIiwic3R1ZHlfcGVybSI6InR2LWNoYXJ0cGF0dGVybnMsdHYtdm9sdW1lYnlwcmljZSx0di1wcm9zdHVkaWVzLHR2LWNoYXJ0X3BhdHRlcm5zIiwibWF4X3N0dWRpZXMiOjI1LCJtYXhfZnVuZGFtZW50YWxzIjoxMCwibWF4X2NoYXJ0cyI6OCwibWF4X2FjdGl2ZV9hbGVydHMiOjQwMCwibWF4X3N0dWR5X29uX3N0dWR5IjoyNCwiZmllbGRzX3Blcm1pc3Npb25zIjpbInJlZmJvbmRzIl0sIm1heF9hbGVydF9jb25kaXRpb25zIjo1LCJtYXhfb3ZlcmFsbF9hbGVydHMiOjIwMDAsIm1heF9vdmVyYWxsX3dhdGNobGlzdF9hbGVydHMiOjUsIm1heF9hY3RpdmVfcHJpbWl0aXZlX2FsZXJ0cyI6NDAwLCJtYXhfYWN0aXZlX2NvbXBsZXhfYWxlcnRzIjo0MDAsIm1heF9hY3RpdmVfd2F0Y2hsaXN0X2FsZXJ0cyI6MiwibWF4X2Nvbm5lY3Rpb25zIjo1MH0.zOwAbBuFVa_72qXGTGsNR-m7VMvKUWWTfJOxqNJrRjos99imj8zSbZYPR8yb7NXGvghJzazNpdyJW_BIqjYbhkDw3tuaSI8Ig31JGNamgLjefZNQELx_0HVoua2jHawIv4_IiTu0JC80-CbNGIdSddKUdlyhShphazL6A5wvoU8"
WS_URL = "wss://prodata.tradingview.com/socket.io/websocket"
SESSION_ID = "cs_UnjWX3itlj5J"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = os.path.join(LOG_DIR, "collector.log") 