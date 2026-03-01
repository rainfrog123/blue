#!/bin/bash
# CCXT 5-second data collector runner
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION="ccxt_collector"

# Install deps if needed
python3 -c "import ccxt, tabulate" 2>/dev/null || \
    python3 -m pip install -q ccxt tabulate

# Start collector
mkdir -p "$SCRIPT_DIR/data"
tmux kill-session -t $SESSION 2>/dev/null || true
tmux new-session -d -s $SESSION "cd $SCRIPT_DIR && python3 collector.py"

echo "🚀 CCXT Collector Started!"
echo "📈 Session: $SESSION"
echo "🔍 Attach: tmux attach -t $SESSION"
echo "🛑 Stop: tmux kill-session -t $SESSION"
