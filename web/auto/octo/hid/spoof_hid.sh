#!/bin/bash
#
# OctoBrowser HID Spoofing Script
# Generates a new machine-id and clears OctoBrowser storage
#
# Usage:
#   ./spoof_hid.sh              # Generate random HID
#   ./spoof_hid.sh <32-hex>     # Set specific HID
#   ./spoof_hid.sh --restore    # Restore original HID
#

set -e

MACHINE_ID_FILE="/etc/machine-id"
BACKUP_FILE="/etc/machine-id.backup"
OCTO_DIR="$HOME/.Octo Browser"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  OctoBrowser HID Spoofing Tool"
    echo "=============================================="
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

get_current_hid() {
    if [ -f "$MACHINE_ID_FILE" ]; then
        cat "$MACHINE_ID_FILE"
    else
        echo "none"
    fi
}

generate_random_hid() {
    # Generate 32 random hex characters
    python3 -c "import uuid; print(uuid.uuid4().hex)"
}

validate_hid() {
    local hid="$1"
    if [[ ${#hid} -eq 32 && "$hid" =~ ^[0-9a-fA-F]+$ ]]; then
        return 0
    else
        return 1
    fi
}

backup_hid() {
    if [ ! -f "$BACKUP_FILE" ]; then
        print_status "Backing up original machine-id..."
        sudo cp "$MACHINE_ID_FILE" "$BACKUP_FILE"
        print_status "Backup saved to: $BACKUP_FILE"
    else
        print_warning "Backup already exists at: $BACKUP_FILE"
    fi
}

set_hid() {
    local new_hid="$1"
    print_status "Setting new machine-id: $new_hid"
    echo "$new_hid" | sudo tee "$MACHINE_ID_FILE" > /dev/null
    sudo chmod 444 "$MACHINE_ID_FILE"
}

clear_octo_storage() {
    print_status "Clearing OctoBrowser storage..."
    
    if [ -d "$OCTO_DIR" ]; then
        # Remove encrypted storage files
        if [ -f "$OCTO_DIR/local.data" ]; then
            rm -f "$OCTO_DIR/local.data"
            print_status "Removed: local.data"
        fi
        
        if [ -f "$OCTO_DIR/localpersist.data" ]; then
            rm -f "$OCTO_DIR/localpersist.data"
            print_status "Removed: localpersist.data"
        fi
        
        # Optionally clear other session data
        # rm -rf "$OCTO_DIR/bcache" 2>/dev/null || true
        # rm -rf "$OCTO_DIR/webviewengine" 2>/dev/null || true
    else
        print_warning "OctoBrowser directory not found: $OCTO_DIR"
    fi
}

restore_hid() {
    if [ -f "$BACKUP_FILE" ]; then
        print_status "Restoring original machine-id..."
        sudo cp "$BACKUP_FILE" "$MACHINE_ID_FILE"
        sudo chmod 444 "$MACHINE_ID_FILE"
        print_status "Restored from: $BACKUP_FILE"
        print_status "Current HID: $(get_current_hid)"
        
        print_warning "Remember to clear OctoBrowser storage after restoring!"
        echo "  rm -f ~/.Octo\\ Browser/local.data ~/.Octo\\ Browser/localpersist.data"
    else
        print_error "No backup file found at: $BACKUP_FILE"
        exit 1
    fi
}

kill_octobrowser() {
    if pgrep -f "OctoBrowser" > /dev/null; then
        print_status "Stopping OctoBrowser..."
        pkill -f "OctoBrowser" 2>/dev/null || true
        sleep 2
    fi
}

show_info() {
    echo ""
    echo -e "${BLUE}Current Status:${NC}"
    echo "  Machine ID File: $MACHINE_ID_FILE"
    echo "  Current HID:     $(get_current_hid)"
    echo "  Backup File:     $BACKUP_FILE"
    [ -f "$BACKUP_FILE" ] && echo "  Backup HID:      $(cat $BACKUP_FILE)"
    echo "  OctoBrowser Dir: $OCTO_DIR"
    echo ""
}

main() {
    print_header
    
    # Check if running as root for machine-id modification
    if [ "$EUID" -ne 0 ] && [ "$1" != "--info" ]; then
        print_warning "Some operations require root. You may be prompted for sudo password."
    fi
    
    # Handle arguments
    case "${1:-}" in
        --restore|-r)
            restore_hid
            exit 0
            ;;
        --info|-i)
            show_info
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [HID]"
            echo ""
            echo "Options:"
            echo "  (none)        Generate random HID and spoof"
            echo "  <32-hex>      Set specific HID (32 hex characters)"
            echo "  --restore,-r  Restore original HID from backup"
            echo "  --info,-i     Show current HID information"
            echo "  --help,-h     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Random HID"
            echo "  $0 00000000000000000000000000000001   # Specific HID"
            echo "  $0 --restore                          # Restore backup"
            exit 0
            ;;
        "")
            # Generate random HID
            NEW_HID=$(generate_random_hid)
            ;;
        *)
            # Validate provided HID
            if validate_hid "$1"; then
                NEW_HID=$(echo "$1" | tr '[:upper:]' '[:lower:]')
            else
                print_error "Invalid HID format. Must be 32 hexadecimal characters."
                print_error "Example: 00000000000000000000000000000001"
                exit 1
            fi
            ;;
    esac
    
    # Show current state
    show_info
    
    # Confirm action
    echo -e "${YELLOW}This will:${NC}"
    echo "  1. Backup current machine-id (if not already backed up)"
    echo "  2. Set new machine-id: $NEW_HID"
    echo "  3. Kill OctoBrowser if running"
    echo "  4. Clear OctoBrowser encrypted storage"
    echo ""
    read -p "Continue? [y/N] " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Aborted."
        exit 0
    fi
    
    echo ""
    
    # Execute spoofing
    backup_hid
    kill_octobrowser
    set_hid "$NEW_HID"
    clear_octo_storage
    
    # Show result
    echo ""
    echo -e "${GREEN}=============================================="
    echo "  HID Spoofing Complete!"
    echo "==============================================${NC}"
    echo ""
    echo "  Old HID: $(cat $BACKUP_FILE 2>/dev/null || echo 'unknown')"
    echo "  New HID: $(get_current_hid)"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Start OctoBrowser"
    echo "  2. Log in with your account (new device will be registered)"
    echo ""
    echo -e "${YELLOW}To restore original HID:${NC}"
    echo "  $0 --restore"
    echo ""
}

main "$@"
