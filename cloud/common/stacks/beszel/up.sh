#!/usr/bin/env bash
# Bring up Beszel Hub for a host that has hosts/<host>/beszel/HUB.
# Usage: bash cloud/common/stacks/beszel/up.sh <host> [--with-agent]
# First-time bootstrap: bash …/beszel/setup-hub.sh <host>
set -euo pipefail

WITH_AGENT=0
HOST=""
for arg in "$@"; do
  case "$arg" in
    --with-agent) WITH_AGENT=1 ;;
    -*)
      echo "unknown flag: $arg" >&2
      exit 2
      ;;
    *)
      if [[ -z "$HOST" ]]; then HOST="$arg"; else
        echo "usage: $0 <host> [--with-agent]" >&2
        exit 2
      fi
      ;;
  esac
done
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host> [--with-agent]" >&2
  exit 2
fi

STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/beszel"
COMPOSE="$STACK/docker-compose.yml"

if [[ ! -f "$SITE_DIR/HUB" && ! -f "$SITE_DIR/hub" ]]; then
  echo "missing $SITE_DIR/HUB — create it to mark this host as Beszel Hub" >&2
  echo "  or run: bash $STACK/setup-hub.sh $HOST" >&2
  exit 1
fi

mkdir -p "$SITE_DIR/data" "$SITE_DIR/socket" "$SITE_DIR/agent-data"
if [[ ! -f "$SITE_DIR/site.env" && -f "$SITE_DIR/.env" ]]; then
  cp "$SITE_DIR/.env" "$SITE_DIR/site.env"
fi
if [[ ! -f "$SITE_DIR/site.env" ]]; then
  echo "missing $SITE_DIR/site.env — copy from $STACK/.env.example or run setup-hub.sh" >&2
  exit 1
fi
cp "$SITE_DIR/site.env" "$SITE_DIR/.env"

# shellcheck disable=SC1091
set -a
# shellcheck disable=SC1090
source "$SITE_DIR/.env"
set +a

docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

PROFILES=()
if [[ "$WITH_AGENT" == "1" ]] || [[ -n "${TOKEN:-}" && -n "${KEY:-}" ]]; then
  PROFILES+=(--profile agent)
fi

docker compose --project-directory "$SITE_DIR" --env-file "$SITE_DIR/.env" \
  -f "$COMPOSE" "${PROFILES[@]}" up -d
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" ps
echo "Hub UI: ${APP_URL:-http://127.0.0.1:8090}  (or ssh -L 8090:127.0.0.1:8090 <host>)"
