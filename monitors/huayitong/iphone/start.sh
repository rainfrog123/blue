#!/bin/bash
# tmux session huayitong — run on the jailbroken iPhone.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SESSION_NAME="huayitong"
export LANG=UTF-8 LC_ALL=UTF-8 LC_CTYPE=UTF-8

JBROOT=$(ls -d /var/containers/Bundle/Application/.jbroot-*/usr/bin 2>/dev/null | head -1)
PYTHON_BIN="${HUAYITONG_PYTHON:-${JBROOT}/python3}"
TMUX_BIN="${JBROOT}/tmux"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "python3 not found under jbroot"
  exit 1
fi

if "$TMUX_BIN" has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Stopping $SESSION_NAME"
  "$TMUX_BIN" kill-session -t "$SESSION_NAME"
  sleep 1
fi

"$TMUX_BIN" new-session -d -s "$SESSION_NAME" -c "$ROOT" \
  "$PYTHON_BIN" "$ROOT/main.py"

sleep 1
if "$TMUX_BIN" has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "Started. Attach: LANG=UTF-8 $TMUX_BIN attach -t $SESSION_NAME"
else
  echo "Failed — try: $PYTHON_BIN $ROOT/main.py --once"
  exit 1
fi
