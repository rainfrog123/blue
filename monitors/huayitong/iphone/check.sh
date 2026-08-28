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

print_hits() {
  local hit="$1"
  local py="${JBROOT}/python3"
  if [[ ! -x "$py" ]]; then
    tail -40 "$hit"
    return
  fi
  "$py" - "$hit" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
parts = re.split(r"(?=^\[\d{4}-\d{2}-\d{2} )", text, flags=re.M)
recs = [p.strip() for p in parts if p.strip()][-5:]
packed = re.compile(
    r"^\s*(?P<doctor>.+?)"
    r"  (?P<date>\d{4}-\d{2}-\d{2}) (?P<period>\S+)"
    r"  (?P<dept>.+?)"
    r"  status=(?P<status>\S+) avail=(?P<avail>\S+) remain=(?P<remain>\S+) "
    r"¥(?P<fee>\S+)"
    r"  (?P<changes>.+?)"
    r"  id=(?P<id>\S+)"
    r"  (?P<place>.*)$"
)
status_re = re.compile(
    r"status=(?P<status>\S+)\s+avail=(?P<avail>\S+)\s+remain=(?P<remain>\S+)\s+¥(?P<fee>\S+)"
)


def short_changes(raw):
    s = raw or ""
    s = (
        s.replace("availableCount:", "avail")
        .replace("remainingNum:", "remain")
        .replace("status:", "st")
        .replace(" → ", "→")
        .replace(",", "")
    )
    return re.sub(r"\s+", " ", s).strip()


def short_name(raw):
    s = (raw or "").strip()
    if "(" in s:
        s = s[: s.index("(")].strip()
    return s or "?"


def compact(rec):
    lines = [ln.strip() for ln in rec.splitlines() if ln.strip()]
    if not lines:
        return rec
    stamp_m = re.match(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", lines[0])
    stamp = stamp_m.group(1) if stamp_m else lines[0]
    doctor = when = status = avail = remain = fee = changes = ""
    rest = lines[1:]
    if rest and packed.match(rest[0]):
        g = packed.match(rest[0]).groupdict()
        doctor, when = g["doctor"], f"{g['date']} {g['period']}"
        status, avail, remain, fee, changes = (
            g["status"], g["avail"], g["remain"], g["fee"], g["changes"],
        )
    else:
        if rest:
            doctor = rest[0]
        if len(rest) > 1:
            when = rest[1]
        for ln in rest:
            sm = status_re.search(ln)
            if sm:
                status, avail, remain, fee = sm.group("status", "avail", "remain", "fee")
            elif "→" in ln and not ln.startswith("id="):
                changes = ln
    head = f"[{stamp}] {short_name(doctor)}  {when}".rstrip()
    ch = short_changes(changes)
    if ch:
        stats = f"{ch}  ¥{fee}"
    else:
        stats = f"status={status} avail={avail} remain={remain}  ¥{fee}"
    return f"{head}\n  {stats}"


chunks = [compact(r) for r in recs]
print("\n\n".join(chunks))
if chunks:
    print()
PY
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
  echo
  local hit="${SCRIPT_DIR}/hits-${slug}.log"
  echo "----- hits-${slug} -----"
  if [[ -f "$hit" ]]; then
    print_hits "$hit"
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
echo
echo "$slugs" | while read -r slug; do
  [[ -n "$slug" ]] || continue
  dump_one "$slug"
done
