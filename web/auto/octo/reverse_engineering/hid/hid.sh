#!/bin/bash
set -e

# ── Config ──────────────────────────────────────────────────────────
MACHINE_ID="/etc/machine-id"
MACHINE_ID_BAK="/etc/machine-id.backup"
OCTO_USER="vncuser"
OCTO_HOME=$(eval echo "~$OCTO_USER")
OCTO_DIR="$OCTO_HOME/.Octo Browser"
OCTO_BIN="/opt/octobrowser/OctoBrowser.AppImage"
OCTO_PORT=59999

# ── Output helpers ──────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' N='\033[0m'
ok()   { echo -e "${G}[+]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[-]${N} $1"; }

# ── Core functions ──────────────────────────────────────────────────

hid_get() { cat "$MACHINE_ID" 2>/dev/null || echo "none"; }

hid_gen() { python3 -c "import uuid; print(uuid.uuid4().hex)"; }

hid_valid() { [[ ${#1} -eq 32 && "$1" =~ ^[0-9a-fA-F]+$ ]]; }

hid_backup() {
    if [ ! -f "$MACHINE_ID_BAK" ]; then
        sudo cp "$MACHINE_ID" "$MACHINE_ID_BAK"
        ok "Backed up to $MACHINE_ID_BAK"
    else
        warn "Backup already exists"
    fi
}

hid_set() {
    echo "$1" | sudo tee "$MACHINE_ID" > /dev/null
    sudo chmod 444 "$MACHINE_ID"
    ok "Machine-id set: $1"
}

hid_restore() {
    [ ! -f "$MACHINE_ID_BAK" ] && { err "No backup found at $MACHINE_ID_BAK"; exit 1; }
    sudo cp "$MACHINE_ID_BAK" "$MACHINE_ID"
    sudo chmod 444 "$MACHINE_ID"
    ok "Restored: $(hid_get)"
    warn "Run '$0 clear' to wipe OctoBrowser storage"
}

# ── OctoBrowser functions ───────────────────────────────────────────

octo_clear() {
    if [ ! -d "$OCTO_DIR" ]; then
        warn "OctoBrowser dir not found: $OCTO_DIR"
        return
    fi
    for f in local.data localpersist.data; do
        [ -f "$OCTO_DIR/$f" ] && rm -f "$OCTO_DIR/$f" && ok "Removed $f"
    done
    echo "$OCTO_PORT" > "$OCTO_DIR/local_port"
    chown "$OCTO_USER:$OCTO_USER" "$OCTO_DIR/local_port"
    ok "Set local_port to $OCTO_PORT"
}

octo_kill() {
    if pgrep -f "OctoBrowser" > /dev/null; then
        ok "Stopping OctoBrowser..."
        pkill -f "OctoBrowser" 2>/dev/null || true
        sleep 2
    fi
}

octo_start() {
    [ ! -f "$OCTO_BIN" ] && { err "AppImage not found: $OCTO_BIN"; return 1; }

    if [ -d "$OCTO_DIR" ]; then
        echo "$OCTO_PORT" > "$OCTO_DIR/local_port"
        chown "$OCTO_USER:$OCTO_USER" "$OCTO_DIR/local_port"
    fi

    ok "Starting OctoBrowser as $OCTO_USER on :1 ..."
    su - "$OCTO_USER" -c "DISPLAY=:1 OCTO_EXTRA_ARGS='--no-sandbox' '$OCTO_BIN' --no-sandbox" &
    sleep 3

    if pgrep -f "OctoBrowser" > /dev/null; then
        ok "Running (PID $(pgrep -f OctoBrowser | head -1)) — API http://localhost:$OCTO_PORT"
    else
        err "Failed to start"
        return 1
    fi
}

# ── Info ────────────────────────────────────────────────────────────

info() {
    echo -e "\n${B}HID Status${N}"
    echo "  machine-id : $(hid_get)"
    [ -f "$MACHINE_ID_BAK" ] && echo "  backup     : $(cat "$MACHINE_ID_BAK")"
    echo "  octo dir   : $OCTO_DIR"
    echo "  octo bin   : $OCTO_BIN"
    echo ""
}

# ── Spoof (default action) ─────────────────────────────────────────

spoof() {
    local new_hid="$1"
    info

    echo -e "${Y}This will:${N}"
    echo "  1. Backup current machine-id"
    echo "  2. Set new machine-id: $new_hid"
    echo "  3. Kill OctoBrowser"
    echo "  4. Clear OctoBrowser storage"
    echo ""
    read -p "Continue? [y/N] " -n 1 -r; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { warn "Aborted."; exit 0; }

    echo ""
    hid_backup
    octo_kill
    hid_set "$new_hid"
    octo_clear

    echo -e "\n${G}Done!${N}  $(cat "$MACHINE_ID_BAK" 2>/dev/null || echo '?') → $(hid_get)\n"

    read -p "Start OctoBrowser now? [y/N] " -n 1 -r; echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""; octo_start
    else
        echo -e "\n${Y}Start later:${N}  $0 start"
    fi
    echo -e "${Y}Restore:${N}  $0 restore\n"
}

# ── Usage ───────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 <command> [args]

Commands:
  spoof [HID]    Spoof machine-id (random if no HID given)
  restore        Restore original machine-id from backup
  clear          Clear OctoBrowser storage files
  start          Start OctoBrowser as $OCTO_USER via VNC
  stop           Stop OctoBrowser
  info           Show current HID and paths

HID must be 32 hex characters. Omit to generate random.

Examples:
  $0                                     # random spoof
  $0 spoof                               # random spoof
  $0 spoof 00000000000000000000000000000001
  $0 restore
  $0 start
EOF
}

# ── Main ────────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        start|-s)       octo_start ;;
        stop)           octo_kill ;;
        clear)          octo_clear ;;
        restore|-r)     hid_restore ;;
        info|-i)        info ;;
        help|-h|--help) usage ;;
        spoof)
            shift
            if [ -n "${1:-}" ]; then
                hid_valid "$1" || { err "Invalid HID: must be 32 hex chars"; exit 1; }
                spoof "$(echo "$1" | tr '[:upper:]' '[:lower:]')"
            else
                spoof "$(hid_gen)"
            fi
            ;;
        "")
            spoof "$(hid_gen)"
            ;;
        *)
            if hid_valid "$1"; then
                spoof "$(echo "$1" | tr '[:upper:]' '[:lower:]')"
            else
                err "Unknown command: $1"
                usage
                exit 1
            fi
            ;;
    esac
}

main "$@"
