#!/usr/bin/env bash
# Usage: bash cloud/common/stacks/beszel-agent/up.sh digi|ali|azure|ali-jp|oracle-tokyo|...
# Per-host secrets: hosts/<host>/beszel-agent/site.env  (HUB_URL, TOKEN, KEY)
# Fleet defaults:   common/stacks/beszel-agent/site.env  (gitignored)
# Seed helper:      stacks/beszel-agent/seed-host.sh
# Skip: hosts/<host>/beszel/HUB  or  hosts/<host>/beszel-agent/SKIP  or  SKIP_BESZEL=1
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # digi|ali|azure|ali-jp|oracle-tokyo|..." >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/beszel-agent"
COMPOSE="$STACK/docker-compose.yml"

if [[ "${SKIP_BESZEL:-0}" == "1" ]]; then
  echo "skip beszel-agent (SKIP_BESZEL=1)"
  exit 0
fi
if [[ -f "$CLOUD/hosts/$HOST/beszel/HUB" || -f "$CLOUD/hosts/$HOST/beszel/hub" ]]; then
  echo "skip beszel-agent (hosts/$HOST/beszel/HUB — this host runs the Hub)"
  exit 0
fi
if [[ -f "$SITE_DIR/SKIP" || -f "$SITE_DIR/skip" ]]; then
  echo "skip beszel-agent (hosts/$HOST/beszel-agent/SKIP)"
  exit 0
fi

# Ensure site.env has real TOKEN/KEY (clone from GitHub often only has empty .env.example)
if [[ ! -f "$SITE_DIR/site.env" ]] \
  || ! grep -qE '^TOKEN=[^[:space:]]+' "$SITE_DIR/site.env" 2>/dev/null \
  || grep -qE 'AAAA\.\.\.' "$SITE_DIR/site.env" 2>/dev/null; then
  echo "==> seeding beszel-agent site.env for $HOST"
  bash "$STACK/seed-host.sh" "$HOST"
fi

ENV_FILE="$SITE_DIR/site.env"
if [[ ! -f "$ENV_FILE" && -f "$SITE_DIR/.env" ]]; then
  ENV_FILE="$SITE_DIR/.env"
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $SITE_DIR/site.env (HUB_URL / TOKEN / KEY) — run: bash $STACK/seed-host.sh $HOST" >&2
  exit 1
fi

mkdir -p "$SITE_DIR/data"
# Strip CR so compose env does not get HUB_URL=$'https://...\r'
sed 's/\r$//' "$ENV_FILE" >"$SITE_DIR/.env"
# keep site.env clean too
sed 's/\r$//' "$ENV_FILE" >"$SITE_DIR/site.env"
# shellcheck disable=SC1091
set -a
# shellcheck disable=SC1090
source "$SITE_DIR/.env"
set +a
# trim accidental whitespace/CR from values
HUB_URL="${HUB_URL//$'\r'/}"
TOKEN="${TOKEN//$'\r'/}"
KEY="${KEY//$'\r'/}"
LISTEN="${LISTEN//$'\r'/}"
export HUB_URL TOKEN KEY LISTEN
if [[ -z "${HUB_URL:-}" || -z "${TOKEN:-}" || -z "${KEY:-}" ]]; then
  echo "site.env must set HUB_URL, TOKEN, and KEY — run: FORCE_SEED=1 bash $STACK/seed-host.sh $HOST" >&2
  exit 1
fi
if [[ "$HUB_URL" != https://* && "$HUB_URL" != http://* ]]; then
  echo "invalid HUB_URL='$HUB_URL' (check for Windows CRLF in site.env)" >&2
  exit 1
fi

docker compose --project-directory "$SITE_DIR" --env-file "$SITE_DIR/.env" -f "$COMPOSE" up -d
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" ps
