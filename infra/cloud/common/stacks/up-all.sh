#!/usr/bin/env bash
# Bring up all shared proxy stacks for one host.
# Usage: bash infra/cloud/common/stacks/up-all.sh digi|ali|azure
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" || ! "$HOST" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
STACKS="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACKS/../.." && pwd)"
HOSTS="$CLOUD/hosts"

docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

echo "==> hysteria"
bash "$STACKS/hysteria/up.sh" "$HOST"

if [[ -f "$HOSTS/$HOST/ss-rust/site.json" ]]; then
  echo "==> ss-rust"
  bash "$STACKS/ss-rust/up.sh" "$HOST"
else
  echo "==> skip ss-rust (no hosts/$HOST/ss-rust/site.json)"
fi

CF_ENV=""
if [[ -f "$HOSTS/$HOST/cloudflared/site.env" ]]; then
  CF_ENV="$HOSTS/$HOST/cloudflared/site.env"
elif [[ -f "$HOSTS/$HOST/cloudflared/.env" ]]; then
  CF_ENV="$HOSTS/$HOST/cloudflared/.env"
fi

if [[ -n "$CF_ENV" && -f "$HOSTS/$HOST/xray-trojan/site.json" ]]; then
  echo "==> xray-trojan"
  bash "$STACKS/xray-trojan/up.sh" "$HOST"
  echo "==> cloudflared"
  bash "$STACKS/cloudflared/up.sh" "$HOST"
else
  echo "==> skip xray-trojan/cloudflared (need site.json + site.env|.env)"
fi

if [[ -f "$HOSTS/$HOST/xray-reality/site.json" ]]; then
  echo "==> xray-reality"
  bash "$STACKS/xray-reality/up.sh" "$HOST"
else
  echo "==> skip xray-reality (no hosts/$HOST/xray-reality/site.json)"
fi

echo "done: $HOST"
