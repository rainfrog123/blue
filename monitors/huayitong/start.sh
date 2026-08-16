#!/bin/bash
# Restart Huayitong monitor inside a dedicated tmux session.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SESSION_NAME="huayitong"
PYTHON_BIN="${HUAYITONG_PYTHON:-python3}"

if [[ -x /allah/freqtrade/.venv/bin/python3 ]]; then
  PYTHON_BIN="/allah/freqtrade/.venv/bin/python3"
fi

echo "Restarting huayitong monitor..."

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Stopping existing session $SESSION_NAME"
  tmux kill-session -t "$SESSION_NAME"
  sleep 1
fi

mapfile -t pids < <(pgrep -f "$SCRIPT_DIR/main.py" || true)
if ((${#pids[@]})); then
  echo "Killing leftover PIDs: ${pids[*]}"
  kill "${pids[@]}" 2>/dev/null || true
  sleep 1
fi

cd "$SCRIPT_DIR"
tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR" \
  "$PYTHON_BIN" main.py

sleep 1
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Started. Attach: tmux attach -t $SESSION_NAME"
  echo "Stop:           tmux kill-session -t $SESSION_NAME"
else
  echo "Failed to start tmux session — try: $PYTHON_BIN main.py"
  exit 1
fi
