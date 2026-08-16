#!/usr/bin/env bash
# Usage: bash cloud/common/stacks/3x-ui/up.sh ali-jp|azure|…
# Default: SQLite under hosts/<host>/3x-ui/db/
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # digi|ali|azure|ali-jp|..." >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$(cd "$CLOUD/hosts/$HOST/3x-ui" && pwd)"
COMPOSE="$STACK/docker-compose.yml"

if [[ ! -d "$SITE_DIR" ]]; then
  echo "missing $SITE_DIR — create hosts/$HOST/3x-ui first" >&2
  exit 1
fi

mkdir -p "$SITE_DIR/db" "$SITE_DIR/cert" "$SITE_DIR/acme"

# Prefer Hy2 manual certs into panel cert/ when missing
if [[ -d "$CLOUD/hosts/$HOST/hysteria/acme/manual" ]] && ! ls "$SITE_DIR/cert"/*.crt >/dev/null 2>&1; then
  cp -a "$CLOUD/hosts/$HOST/hysteria/acme/manual/." "$SITE_DIR/cert/" 2>/dev/null || true
fi

docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

# Absolute site dir for volume mounts (relative ./cert breaks when -f is outside project dir)
export XUI_SITE_DIR="$SITE_DIR"
printf 'XUI_SITE_DIR=%s\n' "$SITE_DIR" > "$SITE_DIR/.env"

docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" pull
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" up -d
docker compose --project-directory "$SITE_DIR" -f "$COMPOSE" ps

# Apply panel login when site.env present, then seed default inbounds
if [[ -f "$SITE_DIR/site.env" && "${SKIP_XUI_SEED:-0}" != "1" ]]; then
  # shellcheck disable=SC1090
  set -a
  # strip CR for Windows-edited env
  TMP_ENV="$(mktemp)"
  sed 's/\r$//' "$SITE_DIR/site.env" >"$TMP_ENV"
  # shellcheck disable=SC1090
  source "$TMP_ENV"
  rm -f "$TMP_ENV"
  set +a
  if [[ -n "${PANEL_PASS:-}" ]]; then
    echo "==> applying panel login from site.env"
    docker exec 3x-ui /app/x-ui setting \
      -username "${PANEL_USER:-admin}" \
      -password "${PANEL_PASS}" \
      -webBasePath "${PANEL_BASE_PATH:-/}" \
      >/dev/null 2>&1 || echo "warn: panel setting apply failed" >&2
    docker restart 3x-ui >/dev/null 2>&1 || true
    sleep 2
  fi
  echo "==> seeding default inbounds (SS / Hy2 / Trojan)"
  bash "$STACK/seed-inbounds.sh" "$HOST" || echo "warn: seed-inbounds failed" >&2
fi

echo
echo "Panel (SQLite): ssh -L 2053:127.0.0.1:2053 $HOST"
echo "Then open http://127.0.0.1:2053 — path/user in hosts/$HOST/3x-ui/site.env"
echo "DB volume: $SITE_DIR/db"
echo "Certs: $SITE_DIR/cert -> /root/cert"
echo "Clash snippet: $SITE_DIR/clash.snippet.yml"
