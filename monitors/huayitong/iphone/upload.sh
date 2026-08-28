#!/bin/bash
# Edit in blue/monitors/huayitong, then push to the phone.
#   ./iphone/upload.sh                 # USB (iproxy 2222 22 + Host iphone-usb)
#   ./iphone/upload.sh --restart       # then ./start.sh on the phone
#   HOST=iphone ./iphone/upload.sh     # Wi-Fi
# Does not touch phone_config.json, hits-*.log, state-*.json, or .env

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="/var/mobile/huayitong"
HOST="${HOST:-iphone-usb}"
RESTART=0

usage() {
  echo "usage: $0 [--restart] [iphone|iphone-usb]" >&2
  exit 1
}

for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=1 ;;
    iphone|iphone-usb) HOST="$arg" ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
if [[ "$HOST" == "iphone-usb" ]]; then
  SSH_OPTS+=(-o ClearAllForwardings=yes)
fi

ssh_phone() {
  ssh "${SSH_OPTS[@]}" "$HOST" "$@"
}

echo "upload $ROOT -> $HOST:$DEST"

if ! ssh_phone 'test -d /var/mobile/huayitong'; then
  echo "ssh $HOST failed — USB: iproxy 2222 22, or HOST=iphone for Wi-Fi" >&2
  exit 1
fi

EXCLUDES=(
  --exclude '.git'
  --exclude '.env'
  --exclude '__pycache__'
  --exclude '*.pyc'
  --exclude 'phone_config.json'
  --exclude 'hits-*.log'
  --exclude 'state-*.json'
  --exclude 'lizhengyong.txt'
  --exclude 'wujunliang.txt'
  --exclude 'export.txt'
)

if command -v rsync >/dev/null 2>&1; then
  rsync -az --no-owner --no-group \
    "${EXCLUDES[@]}" \
    -e "ssh ${SSH_OPTS[*]}" \
    "$ROOT/main.py" "$ROOT/requirements.txt" "$ROOT/README.md" "$ROOT/project.md" \
    "$ROOT/config" "$ROOT/src" "$ROOT/iphone" \
    "$HOST:$DEST/"
else
  tar -C "$ROOT" -cf - \
    "${EXCLUDES[@]}" \
    main.py requirements.txt README.md project.md config src iphone \
    | ssh_phone "cd '$DEST' && tar xf -"
fi

ssh_phone 'chmod +x /var/mobile/huayitong/iphone/*.sh'

echo "ok (left phone_config.json / hits / state on the phone)"

if [[ "$RESTART" -eq 1 ]]; then
  echo "restarting tmux..."
  ssh_phone 'cd /var/mobile/huayitong/iphone && ./start.sh'
fi
