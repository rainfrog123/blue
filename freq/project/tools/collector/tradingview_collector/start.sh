#!/bin/bash
set -e

PYTHON="/allah/freqtrade/.venv/bin/python3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="collector"

# Install deps if needed
$PYTHON -c "import websocket, pandas, tabulate" 2>/dev/null || \
    $PYTHON -m pip install -q websocket-client pandas tabulate

# Start collector
mkdir -p "$SCRIPT_DIR/data/logs"
tmux kill-session -t $SESSION 2>/dev/null || true
tmux new-session -d -s $SESSION "cd $SCRIPT_DIR && $PYTHON main.py"

echo "🚀 Started! Attach: tmux attach -t $SESSION" 