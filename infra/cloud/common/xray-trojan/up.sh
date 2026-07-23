#!/usr/bin/env bash
# Usage: bash infra/cloud/common/xray-trojan/up.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
SITE_DIR="$CLOUD/$SITE/xray-trojan"
python3 "$(dirname "$0")/render.py" "$SITE"
cd "$SITE_DIR"
docker compose up -d
docker compose ps
