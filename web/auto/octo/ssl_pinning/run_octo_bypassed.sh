#!/bin/bash
#
# OctoBrowser SSL Bypass Launcher
# Runs OctoBrowser with pre-patched SSL libraries using LD_PRELOAD
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPIMAGE="/home/vncuser/Downloads/OctoBrowser.AppImage"
PATCHED_DIR="/tmp/octo_patched_libs"
PROXY_PORT="${PROXY_PORT:-8080}"

echo "=============================================="
echo " OctoBrowser SSL Bypass Launcher"
echo " Using Ghidra-analyzed patches"
echo "=============================================="
echo ""

# Ensure patched libraries exist
if [ ! -f "$PATCHED_DIR/libnss3.so" ] || [ ! -f "$PATCHED_DIR/libssl.so.3" ]; then
    echo "[*] Creating patched libraries..."
    python3 "$SCRIPT_DIR/ghidra_complete_ssl_bypass.py" \
        /tmp/OctoBrowser.AppImage_extracted "$PATCHED_DIR" 2>/dev/null || true
fi

# Verify patches
echo "[*] Verifying patches..."
for lib in libnss3.so libssl.so.3 libcrypto.so.3; do
    if [ -f "$PATCHED_DIR/$lib" ]; then
        echo "    [OK] $lib"
    else
        echo "    [MISSING] $lib"
    fi
done

# Kill any existing instances
pkill -f "OctoBrowser" 2>/dev/null || true
pkill -f "_MEI" 2>/dev/null || true
rm -rf /tmp/_MEI* 2>/dev/null || true

# Start mitmproxy if not running
if [ "${START_PROXY:-1}" = "1" ]; then
    if ! pgrep -f "mitmdump.*$PROXY_PORT" > /dev/null; then
        echo ""
        echo "[*] Starting mitmproxy on port $PROXY_PORT..."
        mitmdump -p "$PROXY_PORT" --ssl-insecure -w "/tmp/octo_capture_$(date +%s).flow" 2>/dev/null &
        sleep 2
    fi
fi

# Monitor for _MEI extraction and patch immediately
patch_on_extraction() {
    echo "[*] Monitoring for extraction..."
    
    for i in {1..100}; do
        MEI_DIR=$(find /tmp -maxdepth 1 -name "_MEI*" -type d 2>/dev/null | head -1)
        
        if [ -n "$MEI_DIR" ]; then
            # Wait a tiny bit for files to be written
            sleep 0.1
            
            # Check if libraries exist
            if [ -f "$MEI_DIR/libnss3.so" ]; then
                echo "[+] Found extraction: $MEI_DIR"
                echo "[*] Patching libraries..."
                
                # Copy ALL patched libraries
                cp "$PATCHED_DIR/libnss3.so" "$MEI_DIR/" 2>/dev/null && echo "    [OK] libnss3.so"
                cp "$PATCHED_DIR/libssl.so.3" "$MEI_DIR/" 2>/dev/null && echo "    [OK] libssl.so.3"
                cp "$PATCHED_DIR/libcrypto.so.3" "$MEI_DIR/" 2>/dev/null && echo "    [OK] libcrypto.so.3"
                
                [ -d "$MEI_DIR/nss" ] && cp "$PATCHED_DIR/libnss3.so" "$MEI_DIR/nss/" 2>/dev/null
                
                echo "[+] Patches applied!"
                return 0
            fi
        fi
        
        sleep 0.05
    done
    
    echo "[!] Timeout waiting for extraction"
    return 1
}

echo ""
echo "[*] Starting OctoBrowser..."

# Start the patcher in background - it will patch as soon as extraction happens
patch_on_extraction &
PATCHER_PID=$!

# Give patcher a moment to start
sleep 0.2

# Run OctoBrowser
DISPLAY="${DISPLAY:-:1}"
export DISPLAY
export http_proxy="http://127.0.0.1:$PROXY_PORT"
export https_proxy="http://127.0.0.1:$PROXY_PORT"

# Use LD_PRELOAD to try to load our libraries first (might not work with PyInstaller but worth trying)
export LD_PRELOAD="$PATCHED_DIR/libnss3.so:$PATCHED_DIR/libssl.so.3:$PATCHED_DIR/libcrypto.so.3"

if command -v proxychains4 &> /dev/null; then
    proxychains4 -q "$APPIMAGE" --no-sandbox "$@" &
else
    "$APPIMAGE" --no-sandbox "$@" &
fi

APP_PID=$!

# Wait for patcher
wait $PATCHER_PID 2>/dev/null || true

echo ""
echo "=============================================="
echo " OctoBrowser running (PID: $APP_PID)"
echo " Traffic captured to /tmp/octo_capture_*.flow"
echo "=============================================="

# Don't wait - return immediately so user can interact
