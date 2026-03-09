#!/bin/bash
# Start OctoBrowser with proper sandbox flags for root/VNC

set -e

OCTO_USER="vncuser"
OCTO_HOME=$(eval echo "~$OCTO_USER")
OCTO_DIR="$OCTO_HOME/.Octo Browser"
OCTO_BIN="/opt/octobrowser/OctoBrowser.AppImage"
OCTO_PORT=56933

G='\033[0;32m' R='\033[0;31m' Y='\033[1;33m' N='\033[0m'
ok()  { echo -e "${G}[+]${N} $1"; }
err() { echo -e "${R}[-]${N} $1"; }

# Ensure port file exists
if [ -d "$OCTO_DIR" ]; then
    echo "$OCTO_PORT" > "$OCTO_DIR/local_port"
    chown "$OCTO_USER:$OCTO_USER" "$OCTO_DIR/local_port" 2>/dev/null || true
fi

# Check binary
[ ! -f "$OCTO_BIN" ] && { err "AppImage not found: $OCTO_BIN"; exit 1; }

# Start
ok "Starting OctoBrowser as $OCTO_USER on :1 ..."
su - "$OCTO_USER" -c "DISPLAY=:1 OCTO_EXTRA_ARGS='--no-sandbox' '$OCTO_BIN' --no-sandbox" &
sleep 3

if pgrep -f "OctoBrowser" > /dev/null; then
    ok "Running (PID $(pgrep -f OctoBrowser | head -1))"
    ok "API: http://localhost:$OCTO_PORT"
else
    err "Failed to start"
    exit 1
fi
