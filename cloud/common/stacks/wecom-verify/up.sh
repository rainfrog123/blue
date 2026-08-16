#!/usr/bin/env bash
# Usage: bash cloud/common/stacks/wecom-verify/up.sh ali-jp
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # ali-jp|..." >&2
  exit 2
fi
STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/wecom-verify"
COMPOSE="$STACK/docker-compose.yml"
ENV_FILE="$SITE_DIR/site.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE (copy site.env.example)" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
# strip Windows CR if present
source <(sed 's/\r$//' "$ENV_FILE")
set +a

for v in WECOM_TOKEN WECOM_AES_KEY WECOM_CORP_ID; do
  if [[ -z "${!v:-}" ]]; then
    echo "missing $v in $ENV_FILE" >&2
    exit 1
  fi
done

docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

docker compose --project-directory "$STACK" --env-file "$ENV_FILE" \
  -f "$COMPOSE" up -d --build
docker compose --project-directory "$STACK" -f "$COMPOSE" ps
