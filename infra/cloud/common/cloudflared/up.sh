#!/usr/bin/env bash
# Usage: bash infra/cloud/common/cloudflared/up.sh digi|ali|azure
# Per-VPS secret file: <vps>/cloudflared/.env  (CF_TUNNEL_TOKEN=...)
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
SITE_DIR="$CLOUD/$SITE/cloudflared"
ENV_FILE=""
if [[ -f "$SITE_DIR/.env" ]]; then
  ENV_FILE="$SITE_DIR/.env"
elif [[ -f "$SITE_DIR/site.env" ]]; then
  ENV_FILE="$SITE_DIR/site.env"
else
  echo "missing $SITE_DIR/.env (CF_TUNNEL_TOKEN=...)" >&2
  exit 1
fi
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
cd "$SITE_DIR"
# Normalize to .env for compose env_file
if [[ "$(basename "$ENV_FILE")" != ".env" ]]; then
  cp "$ENV_FILE" "$SITE_DIR/.env"
fi
if [[ ! -f docker-compose.yml ]]; then
  cp "$(dirname "$0")/docker-compose.yml" docker-compose.yml
fi
docker compose --env-file .env up -d
docker compose ps
