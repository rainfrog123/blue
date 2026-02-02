#!/bin/bash
#
# OctoBrowser SSL Pinning Bypass - PyInstaller AppImage Edition
# 
# This script monitors for the PyInstaller extraction directory
# and patches the libnss3.so in real-time before the app loads it.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPIMAGE="/home/vncuser/Downloads/OctoBrowser.AppImage"
PATCHED_NSS="/tmp/octo_patched_libs/libnss3.so"
PROXY_PORT="${PROXY_PORT:-8080}"

echo "=================================================="
echo " OctoBrowser SSL Pinning Bypass (PyInstaller Mode)"
echo "=================================================="

# Ensure patched library exists
if [ ! -f "$PATCHED_NSS" ]; then
    echo "[!] Patched libnss3.so not found. Creating..."
    python3 "$SCRIPT_DIR/ghidra_ssl_patcher.py" \
        /tmp/OctoBrowser.AppImage_extracted \
        /tmp/octo_patched_libs
fi

# Verify patch
PATCH_CHECK=$(xxd -s 0x2e960 -l 8 "$PATCHED_NSS" -p 2>/dev/null)
if [ "$PATCH_CHECK" != "f30f1efa31c0c390" ]; then
    echo "[!] ERROR: Patch verification failed!"
    exit 1
fi
echo "[+] Patched NSS library verified"

# Clean up any existing PyInstaller temp directories
echo "[*] Cleaning up old PyInstaller extractions..."
rm -rf /tmp/_MEI* 2>/dev/null || true

# Start mitmproxy if requested
if [ "${START_PROXY:-1}" = "1" ]; then
    if ! pgrep -f "mitmdump.*$PROXY_PORT" > /dev/null; then
        echo "[*] Starting mitmproxy on port $PROXY_PORT..."
        mitmdump -p "$PROXY_PORT" --ssl-insecure -w /tmp/octo_traffic_$(date +%s).flow 2>/dev/null &
        MITM_PID=$!
        echo "[+] mitmproxy started (PID: $MITM_PID)"
        sleep 1
    fi
fi

# Background process to patch the library once extraction happens
patch_extracted_library() {
    echo "[*] Watching for PyInstaller extraction..."
    
    local max_wait=30
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        # Find the _MEI extraction directory
        MEI_DIR=$(find /tmp -maxdepth 1 -name "_MEI*" -type d 2>/dev/null | head -1)
        
        if [ -n "$MEI_DIR" ] && [ -f "$MEI_DIR/libnss3.so" ]; then
            echo "[+] Found extraction: $MEI_DIR"
            
            # Check if already patched
            CHECK=$(xxd -s 0x2e960 -l 8 "$MEI_DIR/libnss3.so" -p 2>/dev/null)
            if [ "$CHECK" != "f30f1efa31c0c390" ]; then
                echo "[*] Patching libnss3.so in $MEI_DIR..."
                cp "$PATCHED_NSS" "$MEI_DIR/libnss3.so"
                
                # Also patch nss subdirectory if exists
                [ -d "$MEI_DIR/nss" ] && cp "$PATCHED_NSS" "$MEI_DIR/nss/libnss3.so" 2>/dev/null
                
                echo "[+] SSL pinning bypassed!"
            else
                echo "[+] Library already patched"
            fi
            return 0
        fi
        
        sleep 0.2
        ((waited++)) || true
    done
    
    echo "[!] Timeout waiting for PyInstaller extraction"
    return 1
}

# Export proxy settings
export http_proxy="http://127.0.0.1:$PROXY_PORT"
export https_proxy="http://127.0.0.1:$PROXY_PORT"
export HTTP_PROXY="http://127.0.0.1:$PROXY_PORT"
export HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT"

echo ""
echo "[*] Starting OctoBrowser..."
echo "[*] The SSL bypass will be applied when the app extracts"
echo ""

# Start the patcher in background
patch_extracted_library &
PATCHER_PID=$!

# Give patcher a moment to start watching
sleep 0.5

# Run OctoBrowser
# Use DISPLAY if set, otherwise try :1
DISPLAY="${DISPLAY:-:1}"
export DISPLAY

# Run with proxychains to ensure traffic goes through mitmproxy
if command -v proxychains4 &> /dev/null; then
    echo "[*] Using proxychains4..."
    proxychains4 -q -f /etc/proxychains4.conf "$APPIMAGE" --no-sandbox "$@" &
else
    "$APPIMAGE" --no-sandbox "$@" &
fi

APP_PID=$!
echo "[*] OctoBrowser PID: $APP_PID"

# Wait for patcher to complete
wait $PATCHER_PID 2>/dev/null || true

echo ""
echo "=================================================="
echo " OctoBrowser running with SSL bypass"
echo " Traffic captured to /tmp/octo_traffic_*.flow"
echo " View with: mitmdump -r /tmp/octo_traffic_*.flow"
echo "=================================================="
echo ""

# Wait for app
wait $APP_PID 2>/dev/null

# Cleanup
[ -n "$MITM_PID" ] && kill $MITM_PID 2>/dev/null || true
