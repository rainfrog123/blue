#!/bin/bash
# Run OctoBrowser with patched SSL libraries using overlay filesystem

OCTO_APP="/home/vncuser/Downloads/OctoBrowser.AppImage"
PATCHED_LIBS="/tmp/octo_overlay/upper"
PROXY_PORT=8080

# Kill any existing instances
pkill -9 -f OctoBrowser 2>/dev/null
sleep 2

# Clean up old extraction directories
rm -rf /tmp/_MEI* 2>/dev/null

# Start mitmproxy if not running
if ! pgrep -f "mitmdump.*$PROXY_PORT" > /dev/null; then
    echo "Starting mitmproxy on port $PROXY_PORT..."
    rm -f /tmp/octo_intercepted.flow /tmp/mitm_intercept.log
    nohup mitmdump -p $PROXY_PORT --ssl-insecure --flow-detail 3 -w /tmp/octo_intercepted.flow > /tmp/mitm_intercept.log 2>&1 &
    sleep 2
fi

echo "Starting OctoBrowser..."
sudo -u vncuser DISPLAY=:1 "$OCTO_APP" --no-sandbox &
OCTO_PID=$!
sleep 2

# Find the extraction directory
EXTRACT_DIR=""
for i in {1..50}; do
    EXTRACT_DIR=$(ls -d /tmp/_MEI* 2>/dev/null | head -1)
    if [ -n "$EXTRACT_DIR" ] && [ -d "$EXTRACT_DIR" ]; then
        break
    fi
    sleep 0.1
done

if [ -z "$EXTRACT_DIR" ]; then
    echo "ERROR: Could not find extraction directory"
    exit 1
fi

echo "Found extraction directory: $EXTRACT_DIR"

# Wait for the libraries to be extracted
sleep 1

# Replace libraries with patched versions
echo "Replacing libraries with patched versions..."
cp -f "$PATCHED_LIBS/libnss3.so" "$EXTRACT_DIR/libnss3.so"
cp -f "$PATCHED_LIBS/libssl.so.3" "$EXTRACT_DIR/libssl.so.3"
cp -f "$PATCHED_LIBS/libcrypto.so.3" "$EXTRACT_DIR/libcrypto.so.3"
chmod 755 "$EXTRACT_DIR"/*.so*

echo "Libraries replaced! Restarting OctoBrowser..."

# Kill and restart to use patched libraries
pkill -9 -f OctoBrowser
sleep 2

# Set up proxychains config
cat > /tmp/proxychains_octo.conf << 'PCCONF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
http 127.0.0.1 8080
PCCONF

# Start OctoBrowser again with proxychains
echo "Starting OctoBrowser with proxy..."
sudo -u vncuser bash -c "
export DISPLAY=:1
proxychains4 -f /tmp/proxychains_octo.conf $OCTO_APP --no-sandbox
" &

sleep 3

# Replace libraries again (in case of fresh extraction)
EXTRACT_DIR=$(ls -d /tmp/_MEI* 2>/dev/null | head -1)
if [ -n "$EXTRACT_DIR" ]; then
    cp -f "$PATCHED_LIBS/libnss3.so" "$EXTRACT_DIR/libnss3.so" 2>/dev/null
    cp -f "$PATCHED_LIBS/libssl.so.3" "$EXTRACT_DIR/libssl.so.3" 2>/dev/null
    cp -f "$PATCHED_LIBS/libcrypto.so.3" "$EXTRACT_DIR/libcrypto.so.3" 2>/dev/null
    echo "Libraries patched in: $EXTRACT_DIR"
fi

echo ""
echo "=== OctoBrowser should now be running with patched SSL libraries ==="
echo "Monitor traffic: tail -f /tmp/mitm_intercept.log"
echo "View captured data: mitmdump -r /tmp/octo_intercepted.flow"
