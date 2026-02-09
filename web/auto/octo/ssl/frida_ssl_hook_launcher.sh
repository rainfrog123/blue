#!/bin/bash
# Launch OctoBrowser with Frida SSL bypass and mitmproxy interception

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRIDA_SCRIPT="$SCRIPT_DIR/frida_ssl_bypass.js"
OCTO_PATH="/home/vncuser/Downloads/OctoBrowser.AppImage"

echo "=== OctoBrowser + Frida SSL Bypass + mitmproxy ==="

# Kill any existing processes
echo "[1/4] Cleaning up existing processes..."
pkill -f OctoBrowser 2>/dev/null
pkill -f mitmdump 2>/dev/null
sleep 2

# Start mitmproxy
echo "[2/4] Starting mitmproxy on port 8080..."
rm -f /tmp/octo_frida.flow /tmp/mitm_frida.log
nohup mitmdump -p 8080 --ssl-insecure --flow-detail 3 -w /tmp/octo_frida.flow > /tmp/mitm_frida.log 2>&1 &
MITM_PID=$!
sleep 2

if ! ps -p $MITM_PID > /dev/null 2>&1; then
    echo "ERROR: mitmproxy failed to start!"
    exit 1
fi
echo "mitmproxy running (PID: $MITM_PID)"

# Start OctoBrowser with Frida
echo "[3/4] Launching OctoBrowser with Frida..."

# Use frida to spawn and inject
export DISPLAY=:1
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Spawn OctoBrowser as vncuser with Frida
echo "[4/4] Attaching Frida SSL bypass..."

# First start OctoBrowser
su - vncuser -c "DISPLAY=:1 HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 proxychains4 -f /etc/proxychains4.conf $OCTO_PATH --no-sandbox" &
sleep 5

# Get the main OctoBrowser PID (the one with most memory usage)
OCTO_PID=$(pgrep -f "OctoBrowser.AppImage" | head -1)

if [ -z "$OCTO_PID" ]; then
    echo "ERROR: OctoBrowser failed to start!"
    exit 1
fi

echo "OctoBrowser started (PID: $OCTO_PID)"
echo "Attaching Frida to PID $OCTO_PID..."

# Attach Frida
frida -p $OCTO_PID -l "$FRIDA_SCRIPT" --no-pause &
FRIDA_PID=$!

echo ""
echo "=== All components running ==="
echo "mitmproxy:   PID $MITM_PID (log: /tmp/mitm_frida.log)"
echo "OctoBrowser: PID $OCTO_PID"
echo "Frida:       PID $FRIDA_PID"
echo ""
echo "Traffic capture: /tmp/octo_frida.flow"
echo ""
echo "To view traffic: tail -f /tmp/mitm_frida.log"
echo "To stop: pkill -f OctoBrowser && pkill -f mitmdump && pkill -f frida"

# Wait for Frida
wait $FRIDA_PID
