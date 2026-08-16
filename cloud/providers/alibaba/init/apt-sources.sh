#!/bin/bash
# Script to replace Aliyun mirrors with official sources permanently
# Run as root

set -e

echo "=== Setting official package sources ==="

# 1. Update global pip config
echo "[1/4] Updating /etc/pip.conf..."
cat > /etc/pip.conf << 'EOF'
[global]
index-url = https://pypi.org/simple/

[install]
trusted-host = pypi.org
               pypi.python.org
               files.pythonhosted.org
EOF

# 2. Update user pip config (for root)
echo "[2/4] Updating /root/.pip/pip.conf..."
mkdir -p /root/.pip
cat > /root/.pip/pip.conf << 'EOF'
[global]
index-url = https://pypi.org/simple/

[install]
trusted-host = pypi.org
               pypi.python.org
               files.pythonhosted.org
EOF

# 3. Update apt sources.list to official Ubuntu mirrors
echo "[3/4] Updating /etc/apt/sources.list..."
cat > /etc/apt/sources.list << 'EOF'
# Official Ubuntu sources for Noble (24.04)
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
EOF

# 4. Prevent cloud-init from overwriting sources on reboot
echo "[4/4] Preserving sources from cloud-init..."
mkdir -p /etc/cloud/cloud.cfg.d
echo "apt_preserve_sources_list: true" > /etc/cloud/cloud.cfg.d/99-preserve-sources.cfg

echo ""
echo "=== Done! Verifying configuration ==="
echo ""
echo "pip index-url:"
pip config get global.index-url 2>/dev/null || echo "  (not set)"
echo ""
echo "apt sources:"
grep -v "^#" /etc/apt/sources.list | grep -v "^$" | head -5
echo ""
echo "Run 'apt update' to refresh package lists."
