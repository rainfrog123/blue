#!/usr/bin/env bash
# Seed default 3x-ui inbounds so the panel is usable right after up/init.
# Usage: bash cloud/common/stacks/3x-ui/seed-inbounds.sh <host>
#
# Idempotent:
#   - Creates SS :12033 if missing
#   - Creates Hy2 :443/udp if cert pair exists (auto self-signed when HY2_SNI known)
#   - Creates Trojan WS :8080 (cloudflared target) if missing
#   - Creates VLESS REALITY :443/tcp if hosts/<host>/3x-ui/REALITY exists (Hy2 stays UDP)
#   - Syncs clients + client_inbounds (required by newer 3x-ui / Xray auth)
#   - Reads/writes tracked inbound.env (Clash secrets) + gitignored site.env (panel)
#   - Writes clash.snippet.yml for copy-paste into blue.yml
#   - Verifies Xray has non-empty clients before declaring ready
#
# Env: SKIP_SS=1  SKIP_HY2=1  SKIP_TROJAN=1  SKIP_REALITY=1  SEED_REALITY=1  FORCE_SEED=1
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>" >&2
  exit 2
fi

STACK="$(cd "$(dirname "$0")" && pwd)"
CLOUD="$(cd "$STACK/../../.." && pwd)"
SITE_DIR="$CLOUD/hosts/$HOST/3x-ui"
DB="$SITE_DIR/db/x-ui.db"
ENV_FILE="$SITE_DIR/site.env"
INBOUND_ENV="$SITE_DIR/inbound.env"
CERT_DIR="$SITE_DIR/cert"
SNIPPET="$SITE_DIR/clash.snippet.yml"

if [[ ! -d "$SITE_DIR" ]]; then
  echo "missing $SITE_DIR" >&2
  exit 1
fi

run() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

rand_alnum() {
  local n="${1:-16}"
  openssl rand -base64 48 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$n" \
    || tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$n"
}

rand_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    python3 -c 'import uuid; print(uuid.uuid4())'
  fi
}

command -v sqlite3 >/dev/null 2>&1 || run apt-get install -y sqlite3 >/dev/null
command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }

echo "==> waiting for 3x-ui + $DB"
for _ in $(seq 1 60); do
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 3x-ui \
    && [[ -f "$DB" ]]; then
    break
  fi
  sleep 1
done
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 3x-ui; then
  echo "3x-ui container not running" >&2
  exit 1
fi
if [[ ! -f "$DB" ]]; then
  echo "missing $DB (panel never initialized)" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if run sqlite3 "$DB" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbounds';" 2>/dev/null | grep -q 1; then
    break
  fi
  sleep 1
done

mkdir -p "$CERT_DIR" "$SITE_DIR/db" "$SITE_DIR/acme"

load_env_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local tmp
  tmp="$(mktemp)"
  sed 's/\r$//' "$f" >"$tmp"
  # shellcheck disable=SC1090
  set -a; source "$tmp"; set +a
  rm -f "$tmp"
}

if [[ ! -f "$ENV_FILE" ]]; then
  PANEL_PASS="$(rand_alnum 24)"
  PANEL_PATH="$(openssl rand -hex 6 2>/dev/null || rand_alnum 12)"
  printf 'PANEL_USER=admin\nPANEL_PASS=%s\nPANEL_BASE_PATH=/%s/\n' \
    "$PANEL_PASS" "$PANEL_PATH" | run tee "$ENV_FILE" >/dev/null
  run chmod 600 "$ENV_FILE" || true
fi

# site.env (panel) then inbound.env (tracked Clash secrets win)
load_env_file "$ENV_FILE"
load_env_file "$INBOUND_ENV"

default_hy2_sni() {
  case "$HOST" in
    ali-jp) echo "hyjp.hyas.site" ;;
    azure) echo "hyaz.hyas.site" ;;
    oracle-tokyo) echo "hyoci.hyas.site" ;;
    oracle-tokyo2) echo "hyoci2.hyas.site" ;;
    oracle-a1) echo "hyocia1.hyas.site" ;;
    vultr-osk) echo "hyvu.hyas.site" ;;
    digi) echo "hydo.hyas.site" ;;
    ali) echo "hyali.hyas.site" ;;
    *) echo "" ;;
  esac
}

HY2_SNI="${HY2_SNI:-$(default_hy2_sni)}"
SS_PASS="${SS_PASS:-}"
HY2_PASS="${HY2_PASS:-}"
TROJAN_PASS="${TROJAN_PASS:-}"
REALITY_UUID="${REALITY_UUID:-}"
REALITY_PRIVKEY="${REALITY_PRIVKEY:-}"
REALITY_PUBKEY="${REALITY_PUBKEY:-}"
REALITY_SHORTID="${REALITY_SHORTID:-}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
REALITY_DEST="${REALITY_DEST:-${REALITY_SNI}:443}"
[[ -n "$SS_PASS" ]] || SS_PASS="$(rand_alnum 16)"
[[ -n "$HY2_PASS" ]] || HY2_PASS="$(rand_alnum 24)"
[[ -n "$TROJAN_PASS" ]] || TROJAN_PASS="$(rand_uuid)"

if [[ "${SKIP_REALITY:-0}" == "1" ]]; then
  :
elif [[ "${SEED_REALITY:-0}" == "1" || -f "$SITE_DIR/REALITY" ]]; then
  SKIP_REALITY=0
else
  SKIP_REALITY=1
fi

if [[ "${SKIP_REALITY}" != "1" ]]; then
  [[ -n "$REALITY_UUID" ]] || REALITY_UUID="$(rand_uuid)"
  [[ -n "$REALITY_SHORTID" ]] || REALITY_SHORTID="$(openssl rand -hex 8 2>/dev/null || rand_alnum 8)"
  if [[ -z "$REALITY_PRIVKEY" || -z "$REALITY_PUBKEY" ]]; then
    echo "==> generating REALITY x25519 keys"
    XRAY_BIN="$(docker exec 3x-ui sh -c 'ls /app/bin/xray-linux-* 2>/dev/null | head -1')"
    KEYS="$(docker exec 3x-ui "$XRAY_BIN" x25519)"
    REALITY_PRIVKEY="$(printf '%s\n' "$KEYS" | awk -F': ' '/^PrivateKey:/{print $2; exit}')"
    REALITY_PUBKEY="$(printf '%s\n' "$KEYS" | awk -F': ' '/PublicKey/{print $2; exit}')"
    if [[ -z "$REALITY_PRIVKEY" || -z "$REALITY_PUBKEY" ]]; then
      echo "failed to parse xray x25519 output:" >&2
      printf '%s\n' "$KEYS" >&2
      exit 1
    fi
  fi
fi

ensure_hy2_cert() {
  local sni="$1"
  [[ -n "$sni" ]] || return 0
  local crt="$CERT_DIR/${sni}.crt"
  local key="$CERT_DIR/${sni}.key"
  local man="$CLOUD/hosts/$HOST/hysteria/acme/manual"
  if [[ -f "$crt" && -f "$key" ]]; then
    return 0
  fi
  if [[ -f "$man/${sni}.crt" && -f "$man/${sni}.key" ]]; then
    run cp -a "$man/${sni}.crt" "$man/${sni}.key" "$CERT_DIR/"
    return 0
  fi
  echo "==> generating self-signed Hy2 cert for $sni"
  run mkdir -p "$man" "$CERT_DIR"
  run openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$man/${sni}.key" \
    -out "$man/${sni}.crt" \
    -days 825 -subj "/CN=${sni}" >/dev/null 2>&1
  run cp -a "$man/${sni}.crt" "$man/${sni}.key" "$CERT_DIR/"
}

if [[ "${SKIP_HY2:-0}" != "1" && -n "$HY2_SNI" ]]; then
  ensure_hy2_cert "$HY2_SNI"
fi

NOW_MS="$(python3 -c 'import time; print(int(time.time()*1000))')"
HY2_ID="$(rand_uuid)"
SQL_FILE="$(mktemp)"
META_FILE="$(mktemp)"

export SEED_HOST="$HOST" SEED_SS_PASS="$SS_PASS" SEED_HY2_PASS="$HY2_PASS"
export SEED_TROJAN_PASS="$TROJAN_PASS" SEED_HY2_SNI="$HY2_SNI" SEED_HY2_ID="$HY2_ID"
export SEED_REALITY_UUID="$REALITY_UUID" SEED_REALITY_PRIVKEY="$REALITY_PRIVKEY"
export SEED_REALITY_PUBKEY="$REALITY_PUBKEY" SEED_REALITY_SHORTID="$REALITY_SHORTID"
export SEED_REALITY_SNI="$REALITY_SNI" SEED_REALITY_DEST="$REALITY_DEST"
export SEED_NOW_MS="$NOW_MS" SEED_SKIP_SS="${SKIP_SS:-0}" SEED_SKIP_HY2="${SKIP_HY2:-0}"
export SEED_SKIP_TROJAN="${SKIP_TROJAN:-0}" SEED_SKIP_REALITY="${SKIP_REALITY:-1}"
export SEED_FORCE="${FORCE_SEED:-0}"
export SEED_CERT_DIR="$CERT_DIR" SEED_SQL="$SQL_FILE" SEED_META="$META_FILE"

# Dump current inbounds as JSON lines (settings contain newlines — avoid TSV)
INBOUND_DUMP="$(mktemp)"
run sqlite3 "$DB" \
  "SELECT json_object('tag', tag, 'port', port, 'protocol', protocol, 'settings', settings) FROM inbounds;" \
  >"$INBOUND_DUMP" || true

export SEED_DUMP="$INBOUND_DUMP"
python3 <<'PY'
import json, os

host = os.environ["SEED_HOST"]
ss_pass = os.environ["SEED_SS_PASS"]
hy2_pass = os.environ["SEED_HY2_PASS"]
trojan_pass = os.environ["SEED_TROJAN_PASS"]
hy2_sni = os.environ.get("SEED_HY2_SNI", "")
hy2_id = os.environ["SEED_HY2_ID"]
reality_uuid = os.environ.get("SEED_REALITY_UUID", "")
reality_priv = os.environ.get("SEED_REALITY_PRIVKEY", "")
reality_pub = os.environ.get("SEED_REALITY_PUBKEY", "")
reality_sid = os.environ.get("SEED_REALITY_SHORTID", "")
reality_sni = os.environ.get("SEED_REALITY_SNI", "www.microsoft.com")
reality_dest = os.environ.get("SEED_REALITY_DEST", "") or f"{reality_sni}:443"
now_ms = int(os.environ["SEED_NOW_MS"])
force = os.environ.get("SEED_FORCE", "0") == "1"
skip_ss = os.environ.get("SEED_SKIP_SS", "0") == "1"
skip_hy2 = os.environ.get("SEED_SKIP_HY2", "0") == "1"
skip_trojan = os.environ.get("SEED_SKIP_TROJAN", "0") == "1"
skip_reality = os.environ.get("SEED_SKIP_REALITY", "1") == "1"
cert_dir = os.environ["SEED_CERT_DIR"]
sql_path = os.environ["SEED_SQL"]
meta_path = os.environ["SEED_META"]
dump_path = os.environ["SEED_DUMP"]

rows = []
with open(dump_path, encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tag = obj.get("tag") or ""
        port = int(obj.get("port") or 0)
        proto = obj.get("protocol") or ""
        settings = obj.get("settings") or ""
        rows.append((tag, port, proto, settings))

by_tag = {r[0]: r for r in rows}

def esc(s: str) -> str:
    return s.replace("'", "''")

def sql_delete(tag: str) -> str:
    return f"DELETE FROM inbounds WHERE tag='{esc(tag)}';"

def sql_insert(remark, port, protocol, settings, stream, tag, sniffing) -> str:
    return (
        "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, "
        "listen, port, protocol, settings, stream_settings, tag, sniffing) VALUES ("
        f"1, 0, 0, 0, '{esc(remark)}', 1, 0, '', {port}, '{esc(protocol)}', "
        f"'{esc(settings)}', '{esc(stream)}', '{esc(tag)}', '{esc(sniffing)}');"
    )

sniff_on = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"]})
sniff_off = json.dumps({"enabled": False, "destOverride": []})
stmts = []
changed = []

def extract_ss_pass(settings: str):
    try:
        data = json.loads(settings)
        return data.get("password") or (data.get("clients") or [{}])[0].get("password")
    except Exception:
        return None

def extract_hy2_pass(settings: str):
    try:
        data = json.loads(settings)
        return (data.get("clients") or [{}])[0].get("auth")
    except Exception:
        return None

def extract_trojan_pass(settings: str):
    try:
        data = json.loads(settings)
        return (data.get("clients") or [{}])[0].get("password")
    except Exception:
        return None

def extract_reality_uuid(settings: str):
    try:
        data = json.loads(settings)
        return (data.get("clients") or [{}])[0].get("id")
    except Exception:
        return None

# Prefer existing inbound passwords so site.env stays truthful
for tag, port, proto, settings in rows:
    if proto == "shadowsocks" and port == 12033:
        p = extract_ss_pass(settings)
        if p:
            ss_pass = p
    if proto == "hysteria" and port == 443:
        p = extract_hy2_pass(settings)
        if p:
            hy2_pass = p
    if proto == "trojan" and port == 8080:
        p = extract_trojan_pass(settings)
        if p:
            trojan_pass = p
    if proto == "vless" and port == 443:
        u = extract_reality_uuid(settings)
        if u:
            reality_uuid = u

def has_tag(tag):
    return tag in by_tag

def has_port_proto(port, proto):
    return any(r[1] == port and r[2] == proto for r in rows)

if not skip_ss:
    tag = "in-12033-tcpudp"
    if force and has_tag(tag):
        stmts.append(sql_delete(tag))
        by_tag.pop(tag, None)
        rows = [r for r in rows if r[0] != tag]
    if not has_tag(tag) and not has_port_proto(12033, "shadowsocks"):
        settings = {
            "clients": [{
                "security": "",
                "password": ss_pass,
                "email": f"ss@{host}",
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": "",
                "comment": "",
                "reset": 0,
                "created_at": now_ms,
                "updated_at": now_ms,
            }],
            "ivCheck": False,
            "method": "chacha20-ietf-poly1305",
            "network": "tcp,udp",
            "password": ss_pass,
        }
        stmts.append(sql_insert(
            f"{host}-ss", 12033, "shadowsocks",
            json.dumps(settings, indent=2),
            json.dumps({"network": "tcp"}),
            tag, sniff_on,
        ))
        changed.append("ss")

crt = os.path.join(cert_dir, f"{hy2_sni}.crt") if hy2_sni else ""
key = os.path.join(cert_dir, f"{hy2_sni}.key") if hy2_sni else ""
if not skip_hy2 and hy2_sni and os.path.isfile(crt) and os.path.isfile(key):
    tag = "in-443-udp"
    if force and has_tag(tag):
        stmts.append(sql_delete(tag))
        by_tag.pop(tag, None)
        rows = [r for r in rows if r[0] != tag]
    if not has_tag(tag) and not has_port_proto(443, "hysteria"):
        settings = {
            "clients": [{
                "id": hy2_id,
                "security": "",
                "auth": hy2_pass,
                "email": f"hy2@{host}",
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": "",
                "comment": "",
                "reset": 0,
                "created_at": now_ms,
                "updated_at": now_ms,
            }]
        }
        stream = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
                "serverName": hy2_sni,
                "certificates": [{
                    "certificateFile": f"/root/cert/{hy2_sni}.crt",
                    "keyFile": f"/root/cert/{hy2_sni}.key",
                }],
            },
        }
        stmts.append(sql_insert(
            f"{host}-hy2", 443, "hysteria",
            json.dumps(settings, indent=2),
            json.dumps(stream),
            tag, sniff_off,
        ))
        changed.append("hy2")

if not skip_trojan:
    tag = "in-8080-tcp"
    if force and has_tag(tag):
        stmts.append(sql_delete(tag))
        by_tag.pop(tag, None)
        rows = [r for r in rows if r[0] != tag]
    if not has_tag(tag) and not has_port_proto(8080, "trojan"):
        settings = {
            "clients": [{
                "security": "",
                "password": trojan_pass,
                "email": f"trojan@{host}",
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": "",
                "comment": "",
                "reset": 0,
                "created_at": now_ms,
                "updated_at": now_ms,
            }],
            "fallbacks": [],
        }
        stream = {
            "network": "ws",
            "security": "none",
            "wsSettings": {"path": "/x7f9k2m4p8", "host": "", "headers": {}},
        }
        stmts.append(sql_insert(
            f"{host}-trojan-cf", 8080, "trojan",
            json.dumps(settings, indent=2),
            json.dumps(stream),
            tag, sniff_on,
        ))
        changed.append("trojan")

if not skip_reality and reality_uuid and reality_priv and reality_pub:
    tag = "in-443-tcp"
    if force and has_tag(tag):
        stmts.append(sql_delete(tag))
        by_tag.pop(tag, None)
        rows = [r for r in rows if r[0] != tag]
    if not has_tag(tag) and not has_port_proto(443, "vless"):
        settings = {
            "clients": [{
                "id": reality_uuid,
                "flow": "xtls-rprx-vision",
                "email": f"reality@{host}",
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": "",
                "comment": "",
                "reset": 0,
                "security": "",
                "created_at": now_ms,
                "updated_at": now_ms,
            }],
            "decryption": "none",
            "encryption": "none",
            "fallbacks": [],
        }
        stream = {
            "network": "tcp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": {
                "show": False,
                "xver": 0,
                "target": reality_dest,
                "dest": reality_dest,
                "serverNames": [reality_sni],
                "privateKey": reality_priv,
                "minClientVer": "1.0.0",
                "maxClientVer": "",
                "maxTimediff": 0,
                "shortIds": [reality_sid],
                "settings": {
                    "publicKey": reality_pub,
                    "fingerprint": "chrome",
                    "serverName": "",
                    "spiderX": "/",
                    "mldsa65Verify": "",
                },
            },
            "tcpSettings": {
                "acceptProxyProtocol": False,
                "header": {"type": "none"},
            },
        }
        stmts.append(sql_insert(
            f"{host}-reality", 443, "vless",
            json.dumps(settings, indent=2),
            json.dumps(stream),
            tag, sniff_on,
        ))
        changed.append("reality")

with open(sql_path, "w", encoding="utf-8") as f:
    f.write("BEGIN;\n")
    for s in stmts:
        f.write(s + "\n")
    f.write("COMMIT;\n")

meta = {
    "changed": changed,
    "ss_pass": ss_pass,
    "hy2_pass": hy2_pass,
    "trojan_pass": trojan_pass,
    "hy2_sni": hy2_sni,
    "reality_uuid": reality_uuid,
    "reality_privkey": reality_priv,
    "reality_pubkey": reality_pub,
    "reality_shortid": reality_sid,
    "reality_sni": reality_sni,
    "reality_dest": reality_dest,
}
with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(meta, f)
PY

if [[ -s "$SQL_FILE" ]] && grep -q INSERT "$SQL_FILE"; then
  echo "==> applying inbound SQL"
  run sqlite3 "$DB" <"$SQL_FILE"
  CHANGED="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["changed"]) or "none")' "$META_FILE")"
else
  CHANGED="none"
fi

# Sync passwords from meta (existing inbound wins)
eval "$(python3 -c '
import json,sys
m=json.load(open(sys.argv[1]))
for k in ("ss_pass","hy2_pass","trojan_pass","hy2_sni",
          "reality_uuid","reality_privkey","reality_pubkey",
          "reality_shortid","reality_sni","reality_dest"):
    v=m.get(k) or ""
    print(f"{k.upper()}={json.dumps(v)}")
print("CHANGED_LIST="+json.dumps(",".join(m.get("changed") or []) or "none"))
' "$META_FILE")"
SS_PASS="$SS_PASS"
HY2_PASS="$HY2_PASS"
TROJAN_PASS="$TROJAN_PASS"
HY2_SNI="$HY2_SNI"
REALITY_UUID="${REALITY_UUID:-}"
REALITY_PRIVKEY="${REALITY_PRIVKEY:-}"
REALITY_PUBKEY="${REALITY_PUBKEY:-}"
REALITY_SHORTID="${REALITY_SHORTID:-}"
REALITY_SNI="${REALITY_SNI:-}"
REALITY_DEST="${REALITY_DEST:-}"
CHANGED="${CHANGED_LIST:-$CHANGED}"

upsert_env() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    run sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" | run tee -a "$ENV_FILE" >/dev/null
  fi
}
upsert_env SS_PASS "$SS_PASS"
upsert_env HY2_PASS "$HY2_PASS"
upsert_env TROJAN_PASS "$TROJAN_PASS"
[[ -n "$HY2_SNI" ]] && upsert_env HY2_SNI "$HY2_SNI"
if [[ "${SKIP_REALITY}" != "1" && -n "$REALITY_UUID" ]]; then
  upsert_env REALITY_UUID "$REALITY_UUID"
  upsert_env REALITY_PRIVKEY "$REALITY_PRIVKEY"
  upsert_env REALITY_PUBKEY "$REALITY_PUBKEY"
  upsert_env REALITY_SHORTID "$REALITY_SHORTID"
  upsert_env REALITY_SNI "$REALITY_SNI"
  upsert_env REALITY_DEST "$REALITY_DEST"
fi

# Tracked inbound.env (git) — Clash/proxy secrets survive clone; panel stays in site.env
{
  echo "# Tracked proxy secrets — keep in sync with network/clash/blue.yml"
  echo "# Panel login: hosts/$HOST/3x-ui/site.env (gitignored)"
  printf 'SS_PASS=%s\nHY2_PASS=%s\n' "$SS_PASS" "$HY2_PASS"
  [[ -n "$HY2_SNI" ]] && printf 'HY2_SNI=%s\n' "$HY2_SNI"
  printf 'TROJAN_PASS=%s\n' "$TROJAN_PASS"
  if [[ "${SKIP_REALITY}" != "1" && -n "$REALITY_UUID" ]]; then
    printf 'REALITY_UUID=%s\n' "$REALITY_UUID"
    printf 'REALITY_PRIVKEY=%s\n' "$REALITY_PRIVKEY"
    printf 'REALITY_PUBKEY=%s\n' "$REALITY_PUBKEY"
    printf 'REALITY_SHORTID=%s\n' "$REALITY_SHORTID"
    printf 'REALITY_SNI=%s\n' "$REALITY_SNI"
    printf 'REALITY_DEST=%s\n' "$REALITY_DEST"
  fi
} | run tee "$INBOUND_ENV" >/dev/null
run chmod 644 "$INBOUND_ENV" || true

# Newer 3x-ui builds Xray clients from clients + client_inbounds (+ client_traffics).
# Inbound.settings JSON alone leaves Xray with empty clients (Hy2 listens but auth fails).
CLIENT_SQL="$(mktemp)"
export SEED_SS_PASS="$SS_PASS" SEED_HY2_PASS="$HY2_PASS" SEED_TROJAN_PASS="$TROJAN_PASS"
export SEED_REALITY_UUID="$REALITY_UUID" SEED_SKIP_REALITY="${SKIP_REALITY:-1}"
export SEED_NOW_MS="$NOW_MS" SEED_CLIENT_SQL="$CLIENT_SQL" SEED_HOST="$HOST"
INBOUND_IDS="$(mktemp)"
run sqlite3 "$DB" \
  "SELECT json_object('id', id, 'tag', tag, 'port', port, 'protocol', protocol) FROM inbounds;" \
  >"$INBOUND_IDS" || true
CLIENT_DUMP="$(mktemp)"
run sqlite3 "$DB" \
  "SELECT json_object('id', id, 'email', email, 'password', password, 'auth', auth, 'uuid', uuid) FROM clients;" \
  >"$CLIENT_DUMP" 2>/dev/null || true
export SEED_INBOUND_IDS="$INBOUND_IDS" SEED_CLIENT_DUMP="$CLIENT_DUMP"

python3 <<'PY'
import json, os

host = os.environ["SEED_HOST"]
ss_pass = os.environ["SEED_SS_PASS"]
hy2_pass = os.environ["SEED_HY2_PASS"]
trojan_pass = os.environ["SEED_TROJAN_PASS"]
reality_uuid = os.environ.get("SEED_REALITY_UUID", "")
now_ms = int(os.environ["SEED_NOW_MS"])
sql_path = os.environ["SEED_CLIENT_SQL"]
skip_ss = os.environ.get("SEED_SKIP_SS", "0") == "1"
skip_hy2 = os.environ.get("SEED_SKIP_HY2", "0") == "1"
skip_trojan = os.environ.get("SEED_SKIP_TROJAN", "0") == "1"
skip_reality = os.environ.get("SEED_SKIP_REALITY", "1") == "1"

def load_jsonl(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return out

def esc(s: str) -> str:
    return (s or "").replace("'", "''")

inbounds = load_jsonl(os.environ["SEED_INBOUND_IDS"])
clients = {c.get("email"): c for c in load_jsonl(os.environ["SEED_CLIENT_DUMP"])}

wanted = []
if not skip_ss:
    wanted.append(("ss", 12033, "shadowsocks", f"ss@{host}", ss_pass, "", "password", ""))
if not skip_hy2:
    wanted.append(("hy2", 443, "hysteria", f"hy2@{host}", "", hy2_pass, "auth", ""))
if not skip_trojan:
    wanted.append(("trojan", 8080, "trojan", f"trojan@{host}", trojan_pass, "", "password", ""))
if not skip_reality and reality_uuid:
    wanted.append(("reality", 443, "vless", f"reality@{host}", "", "", "uuid", reality_uuid))

def find_inbound(port, proto):
    for ib in inbounds:
        if int(ib.get("port") or 0) == port and (ib.get("protocol") or "") == proto:
            return int(ib["id"])
    return None

stmts = []
changed = []
for kind, port, proto, email, password, auth, _mode, uuid in wanted:
    inbound_id = find_inbound(port, proto)
    if inbound_id is None:
        continue
    flow = "xtls-rprx-vision" if kind == "reality" else ""
    cur = clients.get(email)
    need = False
    if cur is None:
        need = True
        stmts.append(
            "INSERT INTO clients (email, sub_id, uuid, password, auth, flow, security, "
            "limit_ip, total_gb, expiry_time, enable, tg_id, comment, reset, created_at, updated_at) "
            f"VALUES ('{esc(email)}', '', '{esc(uuid)}', '{esc(password)}', '{esc(auth)}', '{esc(flow)}', '', "
            f"0, 0, 0, 1, 0, '', 0, {now_ms}, {now_ms});"
        )
    else:
        if ((cur.get("password") or "") != password
                or (cur.get("auth") or "") != auth
                or (cur.get("uuid") or "") != uuid):
            need = True
            stmts.append(
                f"UPDATE clients SET password='{esc(password)}', auth='{esc(auth)}', "
                f"uuid='{esc(uuid)}', flow='{esc(flow)}', "
                f"enable=1, updated_at={now_ms} WHERE email='{esc(email)}';"
            )
    # link + traffic (idempotent)
    stmts.append(
        f"INSERT OR IGNORE INTO client_inbounds (client_id, inbound_id, flow_override, created_at) "
        f"SELECT id, {inbound_id}, '{esc(flow)}', {now_ms} FROM clients WHERE email='{esc(email)}';"
    )
    stmts.append(
        f"UPDATE client_inbounds SET flow_override='{esc(flow)}' "
        f"WHERE inbound_id={inbound_id} AND client_id=(SELECT id FROM clients WHERE email='{esc(email)}');"
    )
    stmts.append(
        f"INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total, reset, last_online) "
        f"SELECT {inbound_id}, 1, '{esc(email)}', 0, 0, 0, 0, 0, 0 "
        f"WHERE NOT EXISTS (SELECT 1 FROM client_traffics WHERE email='{esc(email)}' AND inbound_id={inbound_id});"
    )
    if need:
        changed.append(kind)

with open(sql_path, "w", encoding="utf-8") as f:
    f.write("BEGIN;\n")
    for s in stmts:
        f.write(s + "\n")
    f.write("COMMIT;\n")
open(sql_path + ".changed", "w", encoding="utf-8").write(
    ",".join(changed) if changed else "none"
)
PY

CLIENT_CHANGED="$(cat "${CLIENT_SQL}.changed" 2>/dev/null || echo none)"
if [[ -s "$CLIENT_SQL" ]] && grep -qE 'INSERT|UPDATE' "$CLIENT_SQL"; then
  echo "==> syncing clients table (Xray auth source)"
  run sqlite3 "$DB" <"$CLIENT_SQL"
  if [[ "$CLIENT_CHANGED" != "none" ]]; then
    if [[ "$CHANGED" == "none" ]]; then
      CHANGED="clients:$CLIENT_CHANGED"
    else
      CHANGED="$CHANGED,clients:$CLIENT_CHANGED"
    fi
  fi
fi

rm -f "$SQL_FILE" "$META_FILE" "$INBOUND_DUMP" "$CLIENT_SQL" "${CLIENT_SQL}.changed" "$INBOUND_IDS" "$CLIENT_DUMP"

PUBLIC_IP="$(curl -4 -fsS --max-time 5 ifconfig.me 2>/dev/null \
  || curl -4 -fsS --max-time 5 icanhazip.com 2>/dev/null \
  || hostname -I 2>/dev/null | awk '{print $1}' \
  || echo "SERVER_IP")"
PUBLIC_IP="$(echo "$PUBLIC_IP" | tr -d '[:space:]')"

{
  echo "# Auto-generated by seed-inbounds.sh for host=$HOST"
  echo "# Panel: ssh -L 2053:127.0.0.1:2053 $HOST → http://127.0.0.1:2053${PANEL_BASE_PATH:-/}"
  echo
  echo "  - name: 🇯🇵${HOST}_ss"
  echo "    type: ss"
  echo "    server: $PUBLIC_IP"
  echo "    port: 12033"
  echo "    cipher: chacha20-ietf-poly1305"
  echo "    password: $SS_PASS"
  echo "    udp: true"
  if [[ -n "$HY2_SNI" && -f "$CERT_DIR/${HY2_SNI}.crt" ]]; then
    echo
    echo "  - name: 🇯🇵${HOST}_hy2"
    echo "    type: hysteria2"
    echo "    server: $PUBLIC_IP"
    echo "    port: 443"
    echo "    password: $HY2_PASS"
    echo "    sni: $HY2_SNI"
    echo "    skip-cert-verify: true"
    # no up/down / brutal-opts — BBR (2026-08-08)
  fi
  if [[ "${SKIP_REALITY}" != "1" && -n "$REALITY_UUID" && -n "$REALITY_PUBKEY" ]]; then
    echo
    echo "  - name: 🇯🇵${HOST}_reality"
    echo "    type: vless"
    echo "    server: $PUBLIC_IP"
    echo "    port: 443"
    echo "    uuid: $REALITY_UUID"
    echo "    network: tcp"
    echo "    tls: true"
    echo "    udp: true"
    echo "    flow: xtls-rprx-vision"
    echo "    servername: $REALITY_SNI"
    echo "    reality-opts:"
    echo "      public-key: $REALITY_PUBKEY"
    echo "      short-id: $REALITY_SHORTID"
    echo "    client-fingerprint: chrome"
  fi
} | run tee "$SNIPPET" >/dev/null
run chmod 600 "$SNIPPET" || true

# Ensure runtime secrets stay gitignored; inbound.env stays tracked
GI="$SITE_DIR/.gitignore"
if [[ ! -f "$GI" ]]; then
  printf '%s\n' \
    '# Runtime / panel-only. Proxy secrets: tracked inbound.env' \
    'db/' 'cert/' 'acme/' '.env' '*.db' '*.db-journal' \
    'site.env' 'clash.snippet.yml' 'ss.password' 'seed-ss.sql' \
    | run tee "$GI" >/dev/null
fi

NEED_RESTART=0
if [[ "$CHANGED" != "none" && -n "$CHANGED" ]]; then
  NEED_RESTART=1
fi

xray_clients_ok() {
  docker exec 3x-ui cat /app/bin/config.json 2>/dev/null | python3 -c '
import json,sys
try:
  c=json.load(sys.stdin)
except Exception:
  sys.exit(1)
want={(12033,"shadowsocks"),(443,"hysteria"),(8080,"trojan"),(443,"vless")}
present=set()
ok_clients={}
for i in c.get("inbounds",[]):
  key=(i.get("port"), i.get("protocol"))
  if key in want:
    present.add(key)
    clients=i.get("settings",{}).get("clients") or []
    ok_clients[key]=len(clients)>0
# SS required; others required only if inbound present
ok = ok_clients.get((12033,"shadowsocks"), False)
for key in present:
  if key[0] in (443, 8080):
    ok = ok and ok_clients.get(key, False)
sys.exit(0 if ok else 1)
' 2>/dev/null
}

if [[ "$NEED_RESTART" == "1" ]] || ! xray_clients_ok; then
  echo "==> restarting 3x-ui so Xray picks up clients ($CHANGED)"
  docker restart 3x-ui >/dev/null
  sleep 4
  if ! xray_clients_ok; then
    echo "warn: Xray clients still empty after restart — check clients/client_inbounds tables" >&2
  else
    echo "==> Xray clients verified (SS/Hy2 auth wired)"
  fi
else
  echo "==> inbounds + clients already present — Xray OK"
fi

echo "==> listeners"
ss -luntp 2>/dev/null | grep -E ':(12033|443|2053)\b' || true

echo
echo "3x-ui ready for host=$HOST"
echo "  Panel:  ssh -L 2053:127.0.0.1:2053 $HOST"
echo "          http://127.0.0.1:2053${PANEL_BASE_PATH:-/}"
echo "          user=${PANEL_USER:-admin}  pass=${PANEL_PASS:-see site.env}"
echo "  SS:     $PUBLIC_IP:12033  pass=$SS_PASS  (chacha20-ietf-poly1305)"
if [[ -n "$HY2_SNI" && -f "$CERT_DIR/${HY2_SNI}.crt" ]]; then
  echo "  Hy2:    $PUBLIC_IP:443/udp  pass=$HY2_PASS  sni=$HY2_SNI"
fi
echo "  Trojan: :8080 WS /x7f9k2m4p8  pass=$TROJAN_PASS  (cloudflared)"
if [[ "${SKIP_REALITY}" != "1" && -n "$REALITY_UUID" ]]; then
  echo "  REALITY: $PUBLIC_IP:443/tcp  uuid=$REALITY_UUID  sni=$REALITY_SNI  (minClientVer=1.0.0)"
fi
echo "  inbound.env (tracked): $INBOUND_ENV"
echo "  site.env (panel):      $ENV_FILE"
echo "  snippet:               $SNIPPET"
