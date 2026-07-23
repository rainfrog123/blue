#!/usr/bin/env bash
# Usage: bash infra/cloud/common/xray-reality/up.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
SITE_DIR="$CLOUD/$SITE/xray-reality"
python3 "$(dirname "$0")/render.py" "$SITE"
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
cd "$SITE_DIR"
docker compose up -d
docker compose ps
