#!/usr/bin/env bash
# Bring up all shared proxy stacks for one VPS.
# Usage: bash infra/cloud/common/up-all.sh digi|ali|azure
set -euo pipefail
SITE="${1:-}"
if [[ -z "$SITE" || ! "$SITE" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  exit 2
fi
COMMON="$(cd "$(dirname "$0")" && pwd)"

echo "==> hysteria"
bash "$COMMON/hysteria/up.sh" "$SITE"

echo "==> ss-rust"
bash "$COMMON/ss-rust/up.sh" "$SITE"

# Tunnel stacks (skip if no .env for cloudflared on this box)
if [[ -f "$COMMON/../$SITE/cloudflared/.env" ]]; then
  echo "==> xray-trojan"
  bash "$COMMON/xray-trojan/up.sh" "$SITE"
  echo "==> cloudflared"
  bash "$COMMON/cloudflared/up.sh" "$SITE"
else
  echo "==> skip xray-trojan/cloudflared (no $SITE/cloudflared/.env)"
fi

# Reality is digi-first; still runnable elsewhere if desired
if [[ "$SITE" == "digi" ]] || [[ -d "$COMMON/../$SITE/xray-reality" ]]; then
  echo "==> xray-reality"
  bash "$COMMON/xray-reality/up.sh" "$SITE"
fi

echo "done: $SITE"
