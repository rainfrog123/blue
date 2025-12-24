#!/bin/bash
# CCXT 5-second data collector runner

PYTHON="/allah/freqtrade/.venv/bin/python3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SCRIPT="$SCRIPT_DIR/collector.py"
DATA_DIR="/allah/data"
LOGS_DIR="$DATA_DIR/logs"
SESSION_NAME="ccxt_collector"

# Check requirements
if [ ! -f "$PYTHON" ]; then
    echo "ERROR: Python not found at $PYTHON"
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
$PYTHON -c "import numpy, ccxt" 2>/dev/null || {
    echo "Installing dependencies..."
    $PYTHON -m pip install -q numpy ccxt
}

# Kill existing session and start new one
tmux kill-session -t $SESSION_NAME 2>/dev/null
echo "Starting CCXT 5s data collector..."
tmux new-session -d -s $SESSION_NAME "cd $SCRIPT_DIR && $PYTHON $COLLECTOR_SCRIPT"

echo "✅ CCXT Collector Started!"
echo "📈 Session: $SESSION_NAME"
echo "🔍 Attach: tmux attach -t $SESSION_NAME"
echo "🛑 Stop: tmux kill-session -t $SESSION_NAME"
echo ""
echo "📋 Monitor logs:"
echo "   tail -f $LOGS_DIR/ccxt_collector.log"

