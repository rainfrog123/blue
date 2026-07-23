#!/usr/bin/env bash
# Usage: bash infra/cloud/common/stacks/ss-rust/up.sh digi|ali|azure
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" || ! "$HOST" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/ss-rust"
COMPOSE="$STACK/docker-compose.yml"
python3 "$STACK/render.py" "$HOST"
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" up -d
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" ps
