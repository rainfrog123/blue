#!/bin/bash
# 5-second data collector runner

# Paths
FREQTRADE_VENV="/allah/freqtrade/.venv/bin/python3"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COLLECTOR_SCRIPT="$SCRIPT_DIR/collector.py"
DATA_DIR="/allah/data"
LOGS_DIR="$DATA_DIR/logs"
SESSION_NAME="data_collector"

# Check requirements
if [ ! -f "$FREQTRADE_VENV" ]; then
    echo "ERROR: Freqtrade venv not found at $FREQTRADE_VENV"
    exit 1
fi

if [ ! -f "$COLLECTOR_SCRIPT" ]; then
    echo "ERROR: collector.py not found"
    exit 1
fi

# Setup directories
mkdir -p "$DATA_DIR" "$LOGS_DIR"
chmod 777 "$DATA_DIR" "$LOGS_DIR"

# Install dependencies if needed
$FREQTRADE_VENV -c "import numpy, psutil, memory_profiler" 2>/dev/null || {
    echo "Installing dependencies..."
    $FREQTRADE_VENV -m pip install numpy psutil memory-profiler aiosqlite
}

# Kill existing session and start new one
tmux kill-session -t $SESSION_NAME 2>/dev/null
echo "Starting 5s data collector..."
tmux new-session -d -s $SESSION_NAME
tmux send-keys -t $SESSION_NAME "$FREQTRADE_VENV $COLLECTOR_SCRIPT" Enter

echo "✅ Data Collector Started!"
echo "📈 Session: $SESSION_NAME"
echo "🔍 Attach: tmux attach -t $SESSION_NAME"
echo "🛑 Stop: tmux kill-session -t $SESSION_NAME"
echo ""
echo "📋 Monitor logs:"
echo "   tail -f $LOGS_DIR/data_collector.log"
echo ""
echo "🎭 This collector uses:"
echo "   - Raw trades (not aggregated)"
echo "   - Precise 5s time boundaries"
echo "   - Millisecond timestamp precision"
echo "   - TradingView-matching OHLCV logic" 