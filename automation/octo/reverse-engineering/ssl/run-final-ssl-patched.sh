#!/bin/bash
#
# OctoBrowser SSL Bypass - Final Launcher
# Runs from pre-patched extraction to avoid race condition
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACTION="/tmp/octo_extracted"
PROXY_PORT="${PROXY_PORT:-8080}"

echo "=============================================="
echo " OctoBrowser SSL Bypass - Final Edition"
echo " Running from pre-patched extraction"
echo "=============================================="

# Ensure extraction exists with patches
if [ ! -d "$EXTRACTION" ] || [ ! -f "$EXTRACTION/PyQt6/Qt6/lib/libQt6WebEngineCore.so.6" ]; then
    echo "[*] Setting up patched extraction..."
    rm -rf "$EXTRACTION"
    cp -a /tmp/OctoBrowser.AppImage_extracted "$EXTRACTION"
    
    # Apply all patches
    cp /tmp/octo_patched_libs/libnss3.so "$EXTRACTION/"
    cp /tmp/octo_patched_libs/libssl.so.3 "$EXTRACTION/"
    cp /tmp/octo_patched_libs/libcrypto.so.3 "$EXTRACTION/"
    cp /tmp/octo_patched_libs/libQt6WebEngineCore.so.6 "$EXTRACTION/PyQt6/Qt6/lib/"
    [ -d "$EXTRACTION/nss" ] && cp /tmp/octo_patched_libs/libnss3.so "$EXTRACTION/nss/"
fi

# Verify Qt patch
PATCH_CHECK=$(xxd -s 0x55df580 -l 5 "$EXTRACTION/PyQt6/Qt6/lib/libQt6WebEngineCore.so.6" -p 2>/dev/null)
if [ "$PATCH_CHECK" = "f30f1efae9" ]; then
    echo "[OK] Qt WebEngine SSL bypass verified"
else
    echo "[WARN] Qt WebEngine patch may be missing"
fi

# Start mitmproxy
if [ "${START_PROXY:-1}" = "1" ]; then
    pkill -f "mitmdump.*$PROXY_PORT" 2>/dev/null
    sleep 1
    mitmdump -p "$PROXY_PORT" --ssl-insecure -w "/tmp/octo_traffic_$(date +%s).flow" 2>&1 &
    sleep 2
    echo "[OK] mitmproxy on port $PROXY_PORT"
fi

# Set up environment
export DISPLAY="${DISPLAY:-:1}"
export LD_LIBRARY_PATH="$EXTRACTION:$EXTRACTION/nss:$EXTRACTION/PyQt6/Qt6/lib:$LD_LIBRARY_PATH"
export PYTHONHOME="$EXTRACTION"
export PYTHONPATH="$EXTRACTION:$EXTRACTION/PYZ.pyz_extracted"
export QT_PLUGIN_PATH="$EXTRACTION/PyQt6/Qt6/plugins"
export QML2_IMPORT_PATH="$EXTRACTION/PyQt6/Qt6/qml"

export http_proxy="http://127.0.0.1:$PROXY_PORT"
export https_proxy="http://127.0.0.1:$PROXY_PORT"

echo ""
echo "[*] Starting OctoBrowser from patched extraction..."
echo "    PYTHONHOME=$PYTHONHOME"
echo "    LD_LIBRARY_PATH includes patched libs"
echo ""

cd "$EXTRACTION"

# Try to find and run the entry point
if [ -x "$EXTRACTION/AppRun" ]; then
    exec proxychains4 -q "$EXTRACTION/AppRun" --no-sandbox "$@"
elif [ -f "$EXTRACTION/main.pyc" ]; then
    exec proxychains4 -q python3 "$EXTRACTION/main.pyc" --no-sandbox "$@"
else
    # Run the original AppImage but with LD_PRELOAD
    exec proxychains4 -q /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox "$@"
fi
