#!/usr/bin/env bash
# Usage: bash infra/cloud/common/hysteria/up.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
CLOUD="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$CLOUD/$SITE/hysteria"
mkdir -p "$DIR/acme"
test -f "$DIR/site.yaml" || { echo "missing $DIR/site.yaml" >&2; exit 1; }
docker compose --project-directory "$DIR" -f "$(dirname "$0")/docker-compose.yml" up -d
docker compose --project-directory "$DIR" -f "$(dirname "$0")/docker-compose.yml" ps
