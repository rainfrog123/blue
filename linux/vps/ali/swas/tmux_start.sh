#!/bin/bash
# Launch SWAS auto-reboot in tmux session
# Usage: ./tmux_start.sh

SESSION="ali_swas"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null

# Start new session
tmux new-session -d -s "$SESSION" -c "$SCRIPT_DIR" "./reboot.sh"

echo "Started tmux session '$SESSION'"
echo "  Attach:  tmux attach -t $SESSION"
echo "  Detach:  Ctrl+B, D"
echo "  Kill:    tmux kill-session -t $SESSION"
