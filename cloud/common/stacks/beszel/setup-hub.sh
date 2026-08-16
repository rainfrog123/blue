#!/usr/bin/env bash
# First-time Beszel Hub bootstrap for a cloud host.
#
# Usage:
#   bash cloud/common/stacks/beszel/setup-hub.sh <host>
#   APP_URL=https://beszel.example.com bash …/setup-hub.sh azure
#
# What it does:
#   1. Marks hosts/<host>/beszel/HUB
#   2. Writes site.env (APP_URL, admin creds)
#   3. Starts Hub on 127.0.0.1:8090 (+ init_tunnel-net for CF)
#   4. Creates admin (PocketBase superuser + app user)
#   5. Enables permanent universal token; fetches Hub public KEY
#   6. Writes TOKEN/KEY into hub site.env + fleet stacks/beszel-agent/site.env
#   7. Starts local agent (same host)
#
# After this: point CF Tunnel hostname → http://beszel:8090, set APP_URL to https://…
# Remote agents: bash …/beszel-agent/up.sh <other-host>
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # digi|ali|azure|ali-jp|..." >&2
  exit 2
fi

STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/beszel"
AGENT_STACK="$CLOUD/common/stacks/beszel-agent"
COMPOSE="$STACK/docker-compose.yml"
HUB_HTTP="${HUB_HTTP:-http://127.0.0.1:8090}"

if [[ ! -d "$CLOUD/hosts/$HOST" ]]; then
  echo "unknown host '$HOST' (no hosts/$HOST)" >&2
  exit 2
fi

mkdir -p "$SITE_DIR/data" "$SITE_DIR/socket" "$SITE_DIR/agent-data"
touch "$SITE_DIR/HUB"
if [[ ! -f "$SITE_DIR/.gitignore" ]]; then
  printf 'site.env\n.env\ndata/\nsocket/\nagent-data/\nadmin.password\n' >"$SITE_DIR/.gitignore"
fi

APP_URL="${APP_URL:-https://beszel.hyas.site}"
BESZEL_BIND="${BESZEL_BIND:-127.0.0.1:8090}"
LOCAL_HUB_URL="${LOCAL_HUB_URL:-http://127.0.0.1:8090}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@blue.local}"
if [[ -z "${ADMIN_PASS:-}" ]]; then
  ADMIN_PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 24)"
fi

# Preserve existing TOKEN/KEY if re-running
OLD_TOKEN=""
OLD_KEY=""
if [[ -f "$SITE_DIR/site.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  # shellcheck disable=SC1090
  source "$SITE_DIR/site.env"
  set +a
  OLD_TOKEN="${TOKEN:-}"
  OLD_KEY="${KEY:-}"
fi

umask 077
{
  echo "APP_URL=${APP_URL}"
  echo "BESZEL_BIND=${BESZEL_BIND}"
  echo "LOCAL_HUB_URL=${LOCAL_HUB_URL}"
  echo "ADMIN_EMAIL=${ADMIN_EMAIL}"
  echo "ADMIN_PASS=${ADMIN_PASS}"
  echo "TOKEN=${OLD_TOKEN}"
  if [[ -n "$OLD_KEY" ]]; then
    echo "KEY=\"${OLD_KEY}\""
  else
    echo "KEY="
  fi
} >"$SITE_DIR/site.env"
printf '%s\n' "$ADMIN_PASS" >"$SITE_DIR/admin.password"
chmod 600 "$SITE_DIR/site.env" "$SITE_DIR/admin.password"
cp "$SITE_DIR/site.env" "$SITE_DIR/.env"

echo "==> ensuring docker network init_tunnel-net"
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net

echo "==> starting Hub (no local agent yet)"
docker compose --project-directory "$SITE_DIR" --env-file "$SITE_DIR/.env" \
  -f "$COMPOSE" up -d beszel

echo "==> waiting for Hub API"
ok=0
for _ in $(seq 1 40); do
  if curl -sS -m 2 "$HUB_HTTP/api/health" 2>/dev/null | grep -q '"code":200'; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" != "1" ]]; then
  echo "Hub did not become healthy at $HUB_HTTP" >&2
  docker logs --tail 40 beszel || true
  exit 1
fi

echo "==> ensuring admin user ($ADMIN_EMAIL)"
# PocketBase superuser (CLI inside container)
docker exec beszel /beszel superuser upsert "$ADMIN_EMAIL" "$ADMIN_PASS" >/dev/null

python3 - <<PY
import json, urllib.request, http.cookiejar, sys

hub = "${HUB_HTTP}"
email = "${ADMIN_EMAIL}"
password = "${ADMIN_PASS}"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def req(method, url, data=None, headers=None):
    h = dict(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    with opener.open(r, timeout=15) as resp:
        return json.load(resp)

# superuser token
st = req("POST", f"{hub}/api/collections/_superusers/auth-with-password",
         {"identity": email, "password": password})["token"]
sh = {"Authorization": st}

# ensure app user exists + verified admin
users = req("GET", f"{hub}/api/collections/users/records", headers=sh)
items = users.get("items") or []
uid = None
for u in items:
    if u.get("email") == email:
        uid = u["id"]
        break
if not uid:
    rec = req("POST", f"{hub}/api/collections/users/records", {
        "email": email,
        "password": password,
        "passwordConfirm": password,
        "username": "admin",
    }, headers=sh)
    uid = rec["id"]
req("PATCH", f"{hub}/api/collections/users/records/{uid}",
    {"verified": True, "role": "admin"}, headers=sh)

# user JWT for beszel endpoints
ut = req("POST", f"{hub}/api/collections/users/auth-with-password",
         {"identity": email, "password": password})["token"]
uh = {"Authorization": ut}

key = req("GET", f"{hub}/api/beszel/getkey", headers=uh)["key"]
tok = req("GET", f"{hub}/api/beszel/universal-token?enable=1&permanent=1", headers=uh)
token = tok["token"]
if not tok.get("active"):
    print("failed to enable universal token", tok, file=sys.stderr)
    sys.exit(1)

out = {
    "token": token,
    "key": key,
    "email": email,
}
print(json.dumps(out))
open("${SITE_DIR}/bootstrap.json", "w").write(json.dumps(out, indent=2) + "\\n")
PY

TOKEN="$(python3 -c "import json; print(json.load(open('${SITE_DIR}/bootstrap.json'))['token'])")"
KEY="$(python3 -c "import json; print(json.load(open('${SITE_DIR}/bootstrap.json'))['key'])")"
chmod 600 "$SITE_DIR/bootstrap.json" 2>/dev/null || true

umask 077
cat >"$SITE_DIR/site.env" <<EOF
APP_URL=${APP_URL}
BESZEL_BIND=${BESZEL_BIND}
LOCAL_HUB_URL=${LOCAL_HUB_URL}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASS=${ADMIN_PASS}
TOKEN=${TOKEN}
KEY="${KEY}"
EOF
cp "$SITE_DIR/site.env" "$SITE_DIR/.env"
chmod 600 "$SITE_DIR/site.env" "$SITE_DIR/.env"

# Fleet agent defaults (gitignored) so init/up-all can seed other hosts
mkdir -p "$AGENT_STACK"
cat >"$AGENT_STACK/site.env" <<EOF
# Written by stacks/beszel/setup-hub.sh on host=${HOST}
HUB_URL=${APP_URL}
TOKEN=${TOKEN}
KEY="${KEY}"
LISTEN=45876
EOF
chmod 600 "$AGENT_STACK/site.env"

echo "==> starting Hub + local agent"
docker compose --project-directory "$SITE_DIR" --env-file "$SITE_DIR/.env" \
  -f "$COMPOSE" --profile agent up -d

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Beszel Hub ready  host=$HOST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  APP_URL:      $APP_URL"
echo "  Local bind:   $BESZEL_BIND"
echo "  Admin:        $ADMIN_EMAIL"
echo "  Password:     $SITE_DIR/admin.password"
echo "  site.env:     $SITE_DIR/site.env"
echo "  Fleet agent:  $AGENT_STACK/site.env"
echo ""
echo "  CF Tunnel (if public): add hostname → http://beszel:8090"
echo "    (Hub must share init_tunnel-net with cloudflared)"
echo "  SSH UI:  ssh -L 8090:127.0.0.1:8090 <ssh-host>"
echo "  Agents:  bash cloud/common/stacks/beszel-agent/up.sh <other-host>"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
