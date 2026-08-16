#!/usr/bin/env bash
# Seed hosts/<host>/beszel-agent/site.env from fleet defaults.
# Usage: bash cloud/common/stacks/beszel-agent/seed-host.sh <host>
#
# Source order:
#   1) common/stacks/beszel-agent/site.env  (fleet secrets — tracked in git)
#   2) first hosts/*/beszel-agent/site.env that already has TOKEN= set
#   3) fail with clear message (do not leave empty .env.example values)
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # digi|ali|azure|ali-jp|oracle-tokyo|..." >&2
  exit 2
fi

STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/beszel-agent"
DEST="$SITE_DIR/site.env"

has_token() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  grep -qE '^TOKEN=[^[:space:]]+' "$f" || return 1
  # reject placeholder from .env.example
  grep -qE '^TOKEN=$' "$f" && return 1
  grep -qE 'AAAA\.\.\.' "$f" && return 1
  return 0
}

SRC=""
if has_token "$STACK/site.env"; then
  SRC="$STACK/site.env"
else
  for f in "$CLOUD"/hosts/*/beszel-agent/site.env; do
    [[ -f "$f" ]] || continue
    if has_token "$f"; then
      SRC="$f"
      break
    fi
  done
fi

if [[ -z "$SRC" ]]; then
  echo "beszel-agent: no fleet secrets found." >&2
  echo "  Put TOKEN/KEY in $STACK/site.env (tracked), or hosts/<host>/beszel-agent/site.env." >&2
  echo "  See $STACK/.env.example" >&2
  exit 1
fi

mkdir -p "$SITE_DIR"
if [[ -f "$DEST" ]] && has_token "$DEST" && [[ "${FORCE_SEED:-0}" != "1" ]]; then
  echo "keep existing $DEST (set FORCE_SEED=1 to overwrite)"
  exit 0
fi

# Normalize CRLF → LF (Windows scp/rsync often breaks HUB_URL → "invalid hub URL")
if command -v sed >/dev/null 2>&1; then
  sed 's/\r$//' "$SRC" >"$DEST"
else
  cp "$SRC" "$DEST"
fi
chmod 600 "$DEST" 2>/dev/null || true
if [[ ! -f "$SITE_DIR/.gitignore" ]]; then
  printf '%s\n' \
    '# Runtime / compose overlay. TOKEN/KEY: tracked site.env' \
    '.env' \
    'data/' \
    >"$SITE_DIR/.gitignore"
fi
echo "seeded $DEST  <-  $SRC"
