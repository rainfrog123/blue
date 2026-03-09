#!/bin/bash
# Quick patch SSL libraries in PyInstaller extraction directory
# This script races to patch libraries before they're fully loaded

PATCHED_DIR="/tmp/patched_ssl"
OCTO_APP="/home/vncuser/Downloads/OctoBrowser.AppImage"

echo "=== OctoBrowser SSL Patcher ==="

# Ensure patched libraries exist
if [ ! -f "$PATCHED_DIR/libnss3.so" ]; then
    echo "ERROR: Patched libraries not found in $PATCHED_DIR"
    exit 1
fi

# Kill any existing OctoBrowser
pkill -9 -f OctoBrowser 2>/dev/null
sleep 2

# Clean up old extraction directories
rm -rf /tmp/_MEI* 2>/dev/null

# Start OctoBrowser in background
echo "Starting OctoBrowser..."
sudo -u vncuser DISPLAY=:1 "$OCTO_APP" --no-sandbox &
OCTO_PID=$!

# Race to find and patch the extraction directory
echo "Waiting for extraction directory..."
EXTRACT_DIR=""
for i in {1..50}; do
    EXTRACT_DIR=$(ls -d /tmp/_MEI* 2>/dev/null | head -1)
    if [ -n "$EXTRACT_DIR" ] && [ -f "$EXTRACT_DIR/libnss3.so" ]; then
        break
    fi
    sleep 0.1
done

if [ -z "$EXTRACT_DIR" ]; then
    echo "ERROR: Could not find extraction directory"
    exit 1
fi

echo "Found extraction directory: $EXTRACT_DIR"

# Quick patch - copy patched libraries
echo "Patching SSL libraries..."
cp -f "$PATCHED_DIR/libnss3.so" "$EXTRACT_DIR/libnss3.so" 2>/dev/null
cp -f "$PATCHED_DIR/libssl.so.3" "$EXTRACT_DIR/libssl.so.3" 2>/dev/null
cp -f "$PATCHED_DIR/libcrypto.so.3" "$EXTRACT_DIR/libcrypto.so.3" 2>/dev/null
chmod 755 "$EXTRACT_DIR"/*.so* 2>/dev/null

echo "Libraries patched!"

# Wait a moment then kill and restart
echo "Restarting OctoBrowser to use patched libraries..."
sleep 2
pkill -9 -f OctoBrowser 2>/dev/null
sleep 1

# The extraction directory might be cleaned up, so we need to patch again
# Start again and patch immediately
sudo -u vncuser DISPLAY=:1 "$OCTO_APP" --no-sandbox &

# Patch again
sleep 0.5
EXTRACT_DIR=$(ls -d /tmp/_MEI* 2>/dev/null | head -1)
if [ -n "$EXTRACT_DIR" ]; then
    cp -f "$PATCHED_DIR/libnss3.so" "$EXTRACT_DIR/libnss3.so" 2>/dev/null
    cp -f "$PATCHED_DIR/libssl.so.3" "$EXTRACT_DIR/libssl.so.3" 2>/dev/null  
    cp -f "$PATCHED_DIR/libcrypto.so.3" "$EXTRACT_DIR/libcrypto.so.3" 2>/dev/null
    chmod 755 "$EXTRACT_DIR"/*.so* 2>/dev/null
    echo "Second patch applied to: $EXTRACT_DIR"
fi

echo "Done! OctoBrowser should now use patched SSL libraries."
echo "Extraction directory: $EXTRACT_DIR"
