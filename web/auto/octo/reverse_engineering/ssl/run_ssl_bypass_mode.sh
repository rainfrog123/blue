#!/bin/bash
#
# OctoBrowser SSL Pinning Bypass Launcher
# Uses Ghidra-analyzed patches to bypass certificate verification
#
# Patched functions in libnss3.so:
#   - CERT_VerifyCertificate      @ 0x2e960
#   - CERT_VerifyCertificateNow   @ 0x2ef60
#   - CERT_VerifyCert             @ 0x2d360
#   - CERT_VerifyCertNow          @ 0x2d380
#   - CERT_PKIXVerifyCert         @ 0x2abc0
#   - CERT_VerifyCertName         @ 0x70e80
#   - CERT_VerifyOCSPResponseSignature @ 0x25900
#   - CERT_VerifyCACertForUsage   @ 0x2c900
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPIMAGE="/home/vncuser/Downloads/OctoBrowser.AppImage"
EXTRACTION_DIR="/tmp/OctoBrowser.AppImage_extracted"
PATCHED_LIBS="/tmp/octo_patched_libs"
PROXY_PORT="${PROXY_PORT:-8080}"

echo "=========================================="
echo " OctoBrowser SSL Pinning Bypass"
echo "=========================================="
echo ""

# Check if patched libs exist
if [ ! -f "$PATCHED_LIBS/libnss3.so" ]; then
    echo "[!] Patched libraries not found. Running patcher..."
    python3 "$SCRIPT_DIR/ghidra_ssl_patcher.py" "$EXTRACTION_DIR" "$PATCHED_LIBS"
fi

# Verify patches
echo "[*] Verifying patched library..."
PATCH_CHECK=$(xxd -s 0x2e960 -l 8 "$PATCHED_LIBS/libnss3.so" -p)
if [ "$PATCH_CHECK" != "f30f1efa31c0c390" ]; then
    echo "[!] WARNING: Patch verification failed!"
    echo "    Expected: f30f1efa31c0c390"
    echo "    Got:      $PATCH_CHECK"
    exit 1
fi
echo "[+] Patch verified: CERT_VerifyCertificate returns SECSuccess"

# Copy patched library to extraction directory
echo "[*] Installing patched library..."
cp "$PATCHED_LIBS/libnss3.so" "$EXTRACTION_DIR/libnss3.so"

# Also copy to nss subdirectory if it exists
if [ -d "$EXTRACTION_DIR/nss" ]; then
    cp "$PATCHED_LIBS/libnss3.so" "$EXTRACTION_DIR/nss/libnss3.so" 2>/dev/null || true
fi

echo "[+] Patched libnss3.so installed"

# Start mitmproxy if not running
if ! pgrep -f "mitmdump.*$PROXY_PORT" > /dev/null; then
    echo ""
    echo "[*] Starting mitmproxy on port $PROXY_PORT..."
    mitmdump -p "$PROXY_PORT" --ssl-insecure -w /tmp/octo_traffic_$(date +%s).flow &
    MITM_PID=$!
    echo "[+] mitmproxy started (PID: $MITM_PID)"
    sleep 2
else
    echo "[*] mitmproxy already running on port $PROXY_PORT"
fi

# Set proxy environment
export http_proxy="http://127.0.0.1:$PROXY_PORT"
export https_proxy="http://127.0.0.1:$PROXY_PORT"
export HTTP_PROXY="http://127.0.0.1:$PROXY_PORT"
export HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT"

# Additional SSL environment variables
export SSL_CERT_FILE=/usr/share/ca-certificates/mozilla/
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export NODE_TLS_REJECT_UNAUTHORIZED=0

echo ""
echo "[*] Proxy configured: 127.0.0.1:$PROXY_PORT"
echo ""

# Find the main executable in extraction
MAIN_EXEC=""
for candidate in "$EXTRACTION_DIR/octobrowser" "$EXTRACTION_DIR/OctoBrowser" "$EXTRACTION_DIR/main"; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        MAIN_EXEC="$candidate"
        break
    fi
done

# If no executable found, look for python entry point
if [ -z "$MAIN_EXEC" ]; then
    # PyInstaller extraction - find the bootstrap
    if [ -f "$EXTRACTION_DIR/octobrowser.py" ]; then
        MAIN_EXEC="python3 $EXTRACTION_DIR/octobrowser.py"
    elif [ -f "$EXTRACTION_DIR/main.py" ]; then
        MAIN_EXEC="python3 $EXTRACTION_DIR/main.py"
    fi
fi

echo "[*] Starting OctoBrowser with patched SSL..."
echo ""
echo "=========================================="

# Method 1: Run from extraction with LD_LIBRARY_PATH
cd "$EXTRACTION_DIR"
export LD_LIBRARY_PATH="$EXTRACTION_DIR:$EXTRACTION_DIR/nss:$LD_LIBRARY_PATH"

# Check what kind of app this is
if [ -f "$EXTRACTION_DIR/octobrowser" ]; then
    # Native executable
    exec ./octobrowser --no-sandbox "$@"
elif [ -f "$EXTRACTION_DIR/OctoBrowser" ]; then
    exec ./OctoBrowser --no-sandbox "$@"
else
    # Likely PyInstaller - run the AppImage but with our patched lib
    # The extraction already happened, so we need to find the entry point
    
    # Try using proxychains with our patched environment
    echo "[*] Using proxychains with patched NSS library..."
    exec proxychains4 -f /etc/proxychains4.conf "$APPIMAGE" --no-sandbox "$@"
fi
