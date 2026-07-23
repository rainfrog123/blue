#!/usr/bin/env bash
# Start Hysteria for one VPS (compose merges common defaults + site.yaml).
# Usage: bash infra/cloud/common/hysteria/up.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
SITE_DIR="$CLOUD/$SITE/hysteria"
mkdir -p "$SITE_DIR/acme"
docker compose -f "$SITE_DIR/docker-compose.yml" up -d
docker compose -f "$SITE_DIR/docker-compose.yml" ps
