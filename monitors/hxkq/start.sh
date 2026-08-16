#!/bin/bash
# Start hxkq monitor in tmux (session name: hxkq).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SESSION_NAME="hxkq"
PYTHON_BIN="${HXKQ_PYTHON:-python3}"

if [[ -x /allah/freqtrade/.venv/bin/python3 ]]; then
  PYTHON_BIN="/allah/freqtrade/.venv/bin/python3"
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Session $SESSION_NAME already running. Use ./restart.sh or ./stop.sh"
  exit 1
fi

cd "$SCRIPT_DIR"
tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR" \
  "$PYTHON_BIN" main.py

sleep 1
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Started. Attach: tmux attach -t $SESSION_NAME"
else
  echo "Failed — try: $PYTHON_BIN main.py"
  exit 1
fi
