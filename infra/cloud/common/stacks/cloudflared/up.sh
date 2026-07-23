#!/usr/bin/env bash
# Usage: bash infra/cloud/common/stacks/cloudflared/up.sh digi|ali|azure
# Per-host secret: hosts/<host>/cloudflared/site.env  (CF_TUNNEL_TOKEN=...)
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" || ! "$HOST" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/cloudflared"
COMPOSE="$STACK/docker-compose.yml"
ENV_FILE=""
if [[ -f "$SITE_DIR/site.env" ]]; then
  ENV_FILE="$SITE_DIR/site.env"
elif [[ -f "$SITE_DIR/.env" ]]; then
  ENV_FILE="$SITE_DIR/.env"
else
  echo "missing $SITE_DIR/site.env (CF_TUNNEL_TOKEN=...)" >&2
  exit 1
fi
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
# Normalize to .env for compose env_file (compose looks in project dir)
if [[ "$(basename "$ENV_FILE")" != ".env" ]]; then
  cp "$ENV_FILE" "$SITE_DIR/.env"
fi
docker compose --project-directory "$SITE_DIR" --env-file "$SITE_DIR/.env" -f "$COMPOSE" up -d
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" ps
