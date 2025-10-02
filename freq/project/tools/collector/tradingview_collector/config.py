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
AUTH_TOKEN = "eyJhbGciOiJSUzUxMiIsImtpZCI6IkdaeFUiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMTY4NjAwNzQsImV4cCI6MTc1OTQ2MTYwMiwiaWF0IjoxNzU5NDQ3MjAyLCJwbGFuIjoicHJvX3ByZW1pdW1fdHJpYWwiLCJwcm9zdGF0dXMiOiJub25fcHJvIiwiZXh0X2hvdXJzIjoxLCJwZXJtIjoiIiwic3R1ZHlfcGVybSI6InR2LXZvbHVtZWJ5cHJpY2UsdHYtcHJvc3R1ZGllcyx0di1jaGFydHBhdHRlcm5zLHR2LWNoYXJ0X3BhdHRlcm5zIiwibWF4X3N0dWRpZXMiOjI1LCJtYXhfZnVuZGFtZW50YWxzIjoxMCwibWF4X2NoYXJ0cyI6OCwibWF4X2FjdGl2ZV9hbGVydHMiOjQwMCwibWF4X3N0dWR5X29uX3N0dWR5IjoyNCwiZmllbGRzX3Blcm1pc3Npb25zIjpbInJlZmJvbmRzIl0sIm1heF9hbGVydF9jb25kaXRpb25zIjo1LCJtYXhfb3ZlcmFsbF9hbGVydHMiOjIwMDAsIm1heF9vdmVyYWxsX3dhdGNobGlzdF9hbGVydHMiOjUsIm1heF9hY3RpdmVfcHJpbWl0aXZlX2FsZXJ0cyI6NDAwLCJtYXhfYWN0aXZlX2NvbXBsZXhfYWxlcnRzIjo0MDAsIm1heF9hY3RpdmVfd2F0Y2hsaXN0X2FsZXJ0cyI6MiwibWF4X2Nvbm5lY3Rpb25zIjo1MH0.uTYluyQ-XZ5Zow4H_eGlR__L4IL25JDJXpXmp5XOp4_1NH9R9ggHchWkX0GjevZ9Ftyd8Jr3MMU90ZkCcq5t7JwgDA6p1GJeS5bWL4uD81zWN6NkmyMcVfr3qerj6q3ObzO6SQjHYceifYamIHxBfjb6BRdtRTePs5lLdJqeiDU"
WS_URL = "wss://prodata.tradingview.com/socket.io/websocket"
SESSION_ID = "cs_UnjWX3itlj5J"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = os.path.join(LOG_DIR, "collector.log") 