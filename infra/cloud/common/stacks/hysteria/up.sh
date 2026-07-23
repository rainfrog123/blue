#!/usr/bin/env bash
# Usage: bash infra/cloud/common/stacks/hysteria/up.sh digi|ali|azure
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" || ! "$HOST" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
DIR="$CLOUD/hosts/$HOST/hysteria"
COMPOSE="$STACK/docker-compose.yml"
mkdir -p "$DIR/acme"
test -f "$DIR/site.yaml" || { echo "missing $DIR/site.yaml" >&2; exit 1; }
ENV_ARGS=()
if [[ -f "$DIR/site.env" ]]; then
  ENV_ARGS=(--env-file "$DIR/site.env")
fi
docker compose --project-directory "$DIR" "${ENV_ARGS[@]}" -f "$COMPOSE" up -d
docker compose --project-directory "$DIR" "${ENV_ARGS[@]}" -f "$COMPOSE" ps
