#!/bin/bash
# Stop hxkq tmux session (does not wipe logs).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SESSION_NAME="hxkq"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  tmux kill-session -t "$SESSION_NAME"
  echo "Stopped session $SESSION_NAME"
else
  echo "No session $SESSION_NAME"
fi

mapfile -t pids < <(pgrep -f "$SCRIPT_DIR/main.py" || true)
if ((${#pids[@]})); then
  kill "${pids[@]}" 2>/dev/null || true
  echo "Killed leftover PIDs: ${pids[*]}"
fi
