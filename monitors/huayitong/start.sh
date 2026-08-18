#!/bin/bash
# Restart Huayitong monitors: one tmux session per active doctor in config/doctors.json.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PYTHON_BIN="${HUAYITONG_PYTHON:-python3}"

if [[ -x /allah/freqtrade/.venv/bin/python3 ]]; then
  PYTHON_BIN="/allah/freqtrade/.venv/bin/python3"
fi

echo "Restarting huayitong monitors..."

if tmux has-session -t huayitong 2>/dev/null; then
  echo "Stopping leftover session huayitong"
  tmux kill-session -t huayitong
fi

mapfile -t pids < <(pgrep -f "$SCRIPT_DIR/main.py" || true)
if ((${#pids[@]})); then
  echo "Killing leftover PIDs: ${pids[*]}"
  kill "${pids[@]}" 2>/dev/null || true
  sleep 1
fi

start_one() {
  local slug="$1"
  local session="huayitong-${slug}"
  if tmux has-session -t "$session" 2>/dev/null; then
    echo "Stopping existing session $session"
    tmux kill-session -t "$session"
    sleep 1
  fi
  tmux new-session -d -s "$session" -c "$SCRIPT_DIR" \
    "$PYTHON_BIN" main.py --doctor "$slug"
  sleep 1
  if tmux has-session -t "$session" 2>/dev/null; then
    echo "Started $session"
  else
    echo "Failed $session — try: $PYTHON_BIN main.py --doctor $slug"
    exit 1
  fi
}

cd "$SCRIPT_DIR"
started=0
doctor_rows=$("$PYTHON_BIN" -c "
import sys
sys.path.insert(0, r'$SCRIPT_DIR')
from config.doctors import iter_start_rows
for slug, active in iter_start_rows():
    print(slug, 1 if active else 0)
")
while read -r slug active; do
  [[ -n "$slug" ]] || continue
  session="huayitong-${slug}"
  if [[ "$active" == "1" ]]; then
    start_one "$slug"
    started=$((started + 1))
  elif tmux has-session -t "$session" 2>/dev/null; then
    echo "Stopping inactive $session"
    tmux kill-session -t "$session"
  fi
done <<EOF
$doctor_rows
EOF

if [[ "$started" -eq 0 ]]; then
  echo "no active doctors in config/doctors.json"
  exit 1
fi
echo "Attach: tmux attach -t huayitong-<slug>"
echo "Stop:   tmux ls | awk '/^huayitong-/ {print \$1}' | cut -d: -f1 | xargs -r -n1 tmux kill-session -t"
