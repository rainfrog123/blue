#!/usr/bin/env bash
# Usage: bash infra/cloud/common/cloudflared/up.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
SITE_DIR="$CLOUD/$SITE/cloudflared"
test -f "$SITE_DIR/site.env" || {
  echo "missing $SITE_DIR/site.env (CF_TUNNEL_TOKEN=...)" >&2
  exit 1
}
# Ensure shared tunnel network exists
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
cd "$SITE_DIR"
docker compose --env-file site.env up -d
docker compose ps
