#!/bin/bash
# Pane + hits dump.
#   ssh iphone /var/mobile/huayitong/iphone/check.sh
#   ssh iphone /var/mobile/huayitong/iphone/check.sh zhaoyu
#   ssh iphone /var/mobile/huayitong/iphone/check.sh combine

unset LC_ALL
export LANG=UTF-8 LC_CTYPE=UTF-8
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
JBROOT=$(ls -d /var/containers/Bundle/Application/.jbroot-*/usr/bin 2>/dev/null | head -1)
TMUX_BIN="${JBROOT}/tmux"

if [[ ! -x "$TMUX_BIN" ]]; then
  echo "tmux not found under jbroot"
  exit 1
fi

if ! "$TMUX_BIN" ls >/dev/null 2>&1; then
  echo "(no tmux — cd /var/mobile/huayitong/iphone && ./start.sh)"
  exit 0
fi

live_slugs() {
  "$TMUX_BIN" ls -F '#{session_name}' | while read -r session; do
    case "$session" in
      huayitong-*) echo "${session#huayitong-}" ;;
    esac
  done
}

dump_one() {
  local slug="$1"
  local session="huayitong-${slug}"
  echo "----- ${session} -----"
  if "$TMUX_BIN" has-session -t "$session" 2>/dev/null; then
    "$TMUX_BIN" capture-pane -t "$session" -p | tail -20
  else
    echo "(no session ${session})"
  fi
  local hit="${SCRIPT_DIR}/hits-${slug}.log"
  echo "----- hits-${slug} -----"
  if [[ -f "$hit" ]]; then
    tail -20 "$hit"
  else
    echo "(no hits-${slug}.log)"
  fi
}

normalize() {
  local raw="$1"
  raw="${raw#huayitong-}"
  echo "$raw"
}

slugs=""
if [[ $# -eq 0 ]]; then
  slugs=$(live_slugs)
elif [[ $# -eq 1 && ( "$1" == "combine" || "$1" == "combined" || "$1" == "all" ) ]]; then
  slugs=$(live_slugs)
else
  for arg in "$@"; do
    slugs="${slugs}$(normalize "$arg")"$'\n'
  done
fi

if [[ -z "${slugs//[$'\n' ]/}" ]]; then
  echo "(no huayitong tmux sessions)"
  "$TMUX_BIN" ls
  exit 0
fi

"$TMUX_BIN" ls
echo "$slugs" | while read -r slug; do
  [[ -n "$slug" ]] || continue
  dump_one "$slug"
done
