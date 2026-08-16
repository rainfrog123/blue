#!/usr/bin/env bash
# Bring up all shared proxy stacks for one host.
# Usage: bash cloud/common/stacks/up-all.sh digi|ali|azure|ali-jp|oracle-a1|...
#
# 3x-ui markers under hosts/<host>/3x-ui/:
#   MIGRATE  → only 3x-ui + cloudflared (skip legacy proxy stacks)
#   ENABLED  → start legacy stacks, then also start 3x-ui
#   (none)   → legacy only; run 3x-ui/up.sh manually if needed
#
# Beszel:
#   Hub   — hosts/<host>/beszel/HUB → stacks/beszel/up.sh
#   Agent — hosts/<host>/beszel-agent/site.env (skipped on Hub host / SKIP_BESZEL=1)
set -euo pipefail
HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # digi|ali|azure|ali-jp|oracle-a1|..." >&2
  exit 2
fi
# shellcheck source=../lib/normalize-host.sh
source "$(cd "$(dirname "$0")/../lib" && pwd)/normalize-host.sh"
HOST="$(normalize_cloud_host "$HOST")"
STACKS="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACKS/../.." && pwd)"
HOSTS="$CLOUD/hosts"
if [[ ! -d "$HOSTS/$HOST" ]]; then
  echo "unknown host '$HOST' (no hosts/$HOST)" >&2
  exit 2
fi

docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

CF_ENV=""
if [[ -f "$HOSTS/$HOST/cloudflared/site.env" ]]; then
  CF_ENV="$HOSTS/$HOST/cloudflared/site.env"
elif [[ -f "$HOSTS/$HOST/cloudflared/.env" ]]; then
  CF_ENV="$HOSTS/$HOST/cloudflared/.env"
fi

up_beszel() {
  if [[ "${SKIP_BESZEL:-0}" == "1" ]]; then
    echo "==> skip beszel (SKIP_BESZEL=1)"
    return 0
  fi
  if [[ -f "$HOSTS/$HOST/beszel/HUB" || -f "$HOSTS/$HOST/beszel/hub" ]]; then
    if [[ -f "$HOSTS/$HOST/beszel/site.env" || -f "$HOSTS/$HOST/beszel/.env" ]]; then
      echo "==> beszel hub"
      bash "$STACKS/beszel/up.sh" "$HOST" || echo "==> warn: beszel hub up failed"
    else
      echo "==> skip beszel hub (HUB marker but no site.env — run stacks/beszel/setup-hub.sh $HOST)"
    fi
    return 0
  fi
  if [[ -f "$HOSTS/$HOST/beszel-agent/site.env" \
     || -f "$HOSTS/$HOST/beszel-agent/.env" \
     || -f "$STACKS/beszel-agent/site.env" ]]; then
    echo "==> beszel-agent"
    bash "$STACKS/beszel-agent/up.sh" "$HOST" || echo "==> warn: beszel-agent up failed"
  else
    echo "==> skip beszel-agent (no site.env — see stacks/beszel-agent/.env.example)"
  fi
}

# --- Migrated host: panel owns SS / Hy2 / Trojan / REALITY ---
if [[ -f "$HOSTS/$HOST/3x-ui/MIGRATE" || -f "$HOSTS/$HOST/3x-ui/migrate" ]]; then
  echo "==> 3x-ui (MIGRATE mode — skip legacy proxy stacks)"
  bash "$STACKS/3x-ui/up.sh" "$HOST"
  if [[ -n "$CF_ENV" ]]; then
    echo "==> cloudflared"
    bash "$STACKS/cloudflared/up.sh" "$HOST"
  else
    echo "==> skip cloudflared (no site.env|.env)"
  fi
  if [[ -f "$HOSTS/$HOST/wecom-verify/site.env" ]]; then
    echo "==> wecom-verify"
    bash "$STACKS/wecom-verify/up.sh" "$HOST" || echo "==> warn: wecom-verify up failed"
  fi
  up_beszel
  echo "done: $HOST (3x-ui migrate)"
  exit 0
fi

# --- Legacy stacks ---
echo "==> hysteria"
bash "$STACKS/hysteria/up.sh" "$HOST"

if [[ -f "$HOSTS/$HOST/ss-rust/site.json" ]]; then
  echo "==> ss-rust"
  bash "$STACKS/ss-rust/up.sh" "$HOST"
else
  echo "==> skip ss-rust (no hosts/$HOST/ss-rust/site.json)"
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

if [[ -f "$HOSTS/$HOST/3x-ui/ENABLED" || -f "$HOSTS/$HOST/3x-ui/enabled" ]]; then
  echo "==> 3x-ui (ENABLED — additive alongside legacy)"
  bash "$STACKS/3x-ui/up.sh" "$HOST"
fi

if [[ -f "$HOSTS/$HOST/wecom-verify/site.env" ]]; then
  echo "==> wecom-verify"
  bash "$STACKS/wecom-verify/up.sh" "$HOST" || echo "==> warn: wecom-verify up failed"
fi

up_beszel
echo "done: $HOST"
