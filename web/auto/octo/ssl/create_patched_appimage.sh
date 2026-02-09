#!/bin/bash
#
# Create a patched OctoBrowser AppImage with SSL bypass
# Uses appimagetool to repack the extracted and patched app
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_APPIMAGE="/home/vncuser/Downloads/OctoBrowser.AppImage"
EXTRACTION_DIR="/tmp/OctoBrowser_patched"
PATCHED_LIBS="/tmp/octo_patched_libs"
OUTPUT_APPIMAGE="/tmp/OctoBrowser_SSL_Bypass.AppImage"

echo "=========================================="
echo " Creating Patched OctoBrowser AppImage"
echo "=========================================="
echo ""

# Step 1: Extract the original AppImage
echo "[1/5] Extracting original AppImage..."
rm -rf "$EXTRACTION_DIR"
cd /tmp

# Extract using the AppImage's built-in extraction
"$ORIGINAL_APPIMAGE" --appimage-extract 2>/dev/null || true
mv squashfs-root "$EXTRACTION_DIR" 2>/dev/null || true

# If that didn't work, use unsquashfs or just run pyinstxtractor
if [ ! -d "$EXTRACTION_DIR" ]; then
    echo "  Standard extraction failed, using alternative method..."
    mkdir -p "$EXTRACTION_DIR"
    cd "$EXTRACTION_DIR"
    
    # Copy from existing extraction
    if [ -d "/tmp/OctoBrowser.AppImage_extracted" ]; then
        cp -a /tmp/OctoBrowser.AppImage_extracted/* "$EXTRACTION_DIR/"
    else
        echo "  [ERROR] No extraction available"
        exit 1
    fi
fi

echo "  Extracted to: $EXTRACTION_DIR"

# Step 2: Ensure patched libraries exist
echo ""
echo "[2/5] Checking patched libraries..."
if [ ! -f "$PATCHED_LIBS/libnss3.so" ]; then
    echo "  Creating patched libraries..."
    python3 "$SCRIPT_DIR/ghidra_complete_ssl_bypass.py" \
        /tmp/OctoBrowser.AppImage_extracted "$PATCHED_LIBS"
fi

# Step 3: Install patched libraries
echo ""
echo "[3/5] Installing patched libraries..."
cp "$PATCHED_LIBS/libcrypto.so.3" "$EXTRACTION_DIR/"
cp "$PATCHED_LIBS/libssl.so.3" "$EXTRACTION_DIR/"
cp "$PATCHED_LIBS/libnss3.so" "$EXTRACTION_DIR/"
[ -d "$EXTRACTION_DIR/nss" ] && cp "$PATCHED_LIBS/libnss3.so" "$EXTRACTION_DIR/nss/"

echo "  [OK] Libraries installed"

# Step 4: Create AppRun script (the entry point)
echo ""
echo "[4/5] Creating AppRun entry point..."
cat > "$EXTRACTION_DIR/AppRun" << 'APPRUN'
#!/bin/bash
# SSL-Bypass enabled OctoBrowser launcher

APPDIR="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="$APPDIR:$APPDIR/nss:$LD_LIBRARY_PATH"
export PYTHONHOME="$APPDIR"
export PYTHONPATH="$APPDIR"

# Find and run the main executable
if [ -f "$APPDIR/octobrowser" ]; then
    exec "$APPDIR/octobrowser" "$@"
elif [ -f "$APPDIR/OctoBrowser" ]; then
    exec "$APPDIR/OctoBrowser" "$@"
else
    # PyInstaller style - find the bootloader
    exec python3 "$APPDIR/main.pyc" "$@"
fi
APPRUN
chmod +x "$EXTRACTION_DIR/AppRun"

# Step 5: Create desktop file if needed
echo ""
echo "[5/5] Creating desktop entry..."
cat > "$EXTRACTION_DIR/octobrowser.desktop" << 'DESKTOP'
[Desktop Entry]
Name=OctoBrowser (SSL Bypass)
Exec=AppRun
Icon=octobrowser
Type=Application
Categories=Network;WebBrowser;
DESKTOP

# Check if appimagetool is available
if command -v appimagetool &> /dev/null; then
    echo ""
    echo "[*] Repacking as AppImage..."
    ARCH=x86_64 appimagetool "$EXTRACTION_DIR" "$OUTPUT_APPIMAGE"
    echo ""
    echo "=========================================="
    echo " Patched AppImage created: $OUTPUT_APPIMAGE"
    echo "=========================================="
else
    echo ""
    echo "[!] appimagetool not found. Run directly from extraction:"
    echo "    $EXTRACTION_DIR/AppRun"
    OUTPUT_APPIMAGE="$EXTRACTION_DIR"
fi

echo ""
echo "To run with mitmproxy:"
echo "  1. Start mitmproxy: mitmdump -p 8080 --ssl-insecure"
echo "  2. Run: proxychains4 $OUTPUT_APPIMAGE --no-sandbox"
