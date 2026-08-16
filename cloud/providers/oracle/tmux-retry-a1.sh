#!/usr/bin/env bash
# Launch Oracle Always Free A1 capacity catcher in a detached tmux session.
#
# Intended host: ali-jp (or any box with ~/.oci + oci SDK).
#
# Usage (from blue repo root or this directory):
#   bash cloud/providers/oracle/Tmux-Retry-A1.sh
#   bash cloud/providers/oracle/Tmux-Retry-A1.sh --foothold
#   INTERVAL=130 SESSION=retry_a1 bash cloud/providers/oracle/Tmux-Retry-A1.sh
#
# Attach / stop:
#   tmux attach -t retry_a1
#   tmux kill-session -t retry_a1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SESSION="${SESSION:-retry_a1}"
INTERVAL="${INTERVAL:-130}"
LOG_FILE="${LOG_FILE:-/var/log/retry_a1.log}"

# Prefer a dedicated venv; fall back to python3 on PATH.
if [[ -n "${PYTHON:-}" ]]; then
  :
elif [[ -x "${HOME}/venv-oci/bin/python" ]]; then
  PYTHON="${HOME}/venv-oci/bin/python"
elif [[ -x "${REPO_ROOT}/.venv-oci/bin/python" ]]; then
  PYTHON="${REPO_ROOT}/.venv-oci/bin/python"
else
  PYTHON="$(command -v python3)"
fi

EXTRA_ARGS=("$@")
CMD=(
  "$PYTHON" "$SCRIPT_DIR/Retry-A1.py"
  --interval "$INTERVAL"
  "${EXTRA_ARGS[@]}"
)

if ! command -v tmux >/dev/null 2>&1; then
  echo "ERROR: tmux not installed" >&2
  exit 1
fi

touch "$LOG_FILE" 2>/dev/null || LOG_FILE="${HOME}/retry_a1.log"
touch "$LOG_FILE"

tmux kill-session -t "$SESSION" 2>/dev/null || true

# shellcheck disable=SC2027,SC2086
tmux new-session -d -s "$SESSION" -c "$REPO_ROOT" \
  "echo \"[\$(date -u +'%Y-%m-%d %H:%M:%S UTC')] starting: ${CMD[*]}\" >>'$LOG_FILE'; ${CMD[*]} 2>&1 | tee -a '$LOG_FILE'; echo \"[\$(date -u +'%Y-%m-%d %H:%M:%S UTC')] exited \$?\" >>'$LOG_FILE'; sleep 5"

echo "Started tmux session '$SESSION' (interval=${INTERVAL}s)"
echo "  python:  $PYTHON"
echo "  log:     $LOG_FILE"
echo "  attach:  tmux attach -t $SESSION"
echo "  kill:    tmux kill-session -t $SESSION"
