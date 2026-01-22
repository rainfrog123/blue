#!/bin/bash
# TradingView 5-second data collector runner
set -e

PYTHON="/allah/freqtrade/.venv/bin/python3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="tv_collector"

# Install deps if needed
$PYTHON -c "import websocket, pandas, tabulate" 2>/dev/null || \
    $PYTHON -m pip install -q websocket-client pandas tabulate

# Start collector
mkdir -p "$SCRIPT_DIR/data"
tmux kill-session -t $SESSION 2>/dev/null || true
tmux new-session -d -s $SESSION "cd $SCRIPT_DIR && $PYTHON collector.py"

echo "🚀 TradingView Collector Started!"
echo "📈 Session: $SESSION"
echo "🔍 Attach: tmux attach -t $SESSION"
echo "🛑 Stop: tmux kill-session -t $SESSION"

