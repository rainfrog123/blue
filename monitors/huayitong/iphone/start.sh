#!/bin/bash
# tmux one session per *active* doctor in config/doctors.json — jailbroken iPhone.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
unset LC_ALL
export LANG=UTF-8 LC_CTYPE=UTF-8

JBROOT=$(ls -d /var/containers/Bundle/Application/.jbroot-*/usr/bin 2>/dev/null | head -1)
PYTHON_BIN="${HUAYITONG_PYTHON:-${JBROOT}/python3}"
TMUX_BIN="${JBROOT}/tmux"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "python3 not found under jbroot"
  exit 1
fi

if "$TMUX_BIN" has-session -t huayitong 2>/dev/null; then
  echo "Stopping leftover huayitong"
  "$TMUX_BIN" kill-session -t huayitong
fi

start_one() {
  local slug="$1"
  local session="huayitong-${slug}"
  if "$TMUX_BIN" has-session -t "$session" 2>/dev/null; then
    echo "Stopping $session"
    "$TMUX_BIN" kill-session -t "$session"
    sleep 1
  fi
  "$TMUX_BIN" new-session -d -s "$session" -c "$ROOT" \
    "$PYTHON_BIN" "$ROOT/main.py" --doctor "$slug"
  sleep 1
  if "$TMUX_BIN" has-session -t "$session" 2>/dev/null; then
    echo "Started $session"
  else
    echo "Failed $session — try: $PYTHON_BIN $ROOT/main.py --doctor $slug --once"
    exit 1
  fi
}

started=0
doctor_rows=$("$PYTHON_BIN" -c "
import sys
sys.path.insert(0, r'$ROOT')
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
  elif "$TMUX_BIN" has-session -t "$session" 2>/dev/null; then
    echo "Stopping inactive $session"
    "$TMUX_BIN" kill-session -t "$session"
  fi
done <<EOF
$doctor_rows
EOF

if [[ "$started" -eq 0 ]]; then
  echo "no active doctors in config/doctors.json"
  exit 1
fi
echo "Attach: LANG=UTF-8 $TMUX_BIN attach -t huayitong-<slug>"
