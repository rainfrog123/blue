#!/bin/bash
#
# DigitalOcean VPS Setup Script
# Configures a fresh Ubuntu server with Docker, Shadowsocks, BBR, and SSH hardening
#
# Target: DO-Premium-Intel (4 vCPU, 8GB RAM, 240GB disk)
#

set -e

# ============================================================================
# COLORS AND HELPERS
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_step() {
    echo -e "${YELLOW}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# ============================================================================
# SYSTEM UPDATE
# ============================================================================
print_header "SYSTEM UPDATE & UPGRADE"

print_step "Updating package lists..."
apt update

print_step "Upgrading installed packages..."
apt upgrade -y

print_success "System updated successfully"

# ============================================================================
# PACKAGE INSTALLATION
# ============================================================================
print_header "INSTALLING PACKAGES"

print_step "Installing Docker and Docker Compose..."
apt install -y docker.io docker-compose

print_step "Installing Git..."
apt install -y git

print_step "Installing utilities (tmux, htop, curl, wget)..."
apt install -y tmux htop curl wget

print_success "All packages installed"

# ============================================================================
# DOCKER SERVICE
# ============================================================================
print_header "DOCKER CONFIGURATION"

print_step "Enabling Docker service..."
systemctl enable docker
systemctl start docker

print_success "Docker enabled and running"

# ============================================================================
# SHADOWSOCKS-RUST SETUP
# ============================================================================
print_header "SHADOWSOCKS-RUST PROXY SERVER"

print_step "Pulling shadowsocks-rust Docker image..."
docker pull teddysun/shadowsocks-rust

print_step "Creating configuration directory..."
mkdir -p /etc/shadowsocks-rust/

print_step "Writing configuration file..."
cat > /etc/shadowsocks-rust/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": 12033,
    "password": "bxsnucrgk6hfish",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "mode": "tcp_and_udp",
    "fast_open": true
}
EOF

print_step "Starting shadowsocks-rust container..."
docker run -d \
    -p 12033:12033 \
    -p 12033:12033/udp \
    --name ss-rust \
    --restart=always \
    -v /etc/shadowsocks-rust:/etc/shadowsocks-rust \
    teddysun/shadowsocks-rust

print_success "Shadowsocks-rust running on port 12033"
print_info "Method: chacha20-ietf-poly1305 | Mode: tcp_and_udp"

# ============================================================================
# TCP BBR & NETWORK OPTIMIZATION
# ============================================================================
print_header "TCP BBR & NETWORK OPTIMIZATION"

print_step "Loading BBR kernel module..."
modprobe tcp_bbr

print_step "Configuring network optimizations..."
tee /etc/sysctl.d/99-network-tuning.conf > /dev/null <<EOF
# BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Disable slow start after idle
net.ipv4.tcp_slow_start_after_idle = 0

# Increase network buffer sizes (16MB max)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# TCP buffer auto-tuning (min, default, max)
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# TCP Fast Open (both directions)
net.ipv4.tcp_fastopen = 3
EOF

print_step "Applying sysctl settings..."
sysctl --system

print_success "BBR and network optimizations enabled"
print_info "Buffer sizes: 16MB max | TCP Fast Open: bidirectional"

# ============================================================================
# GIT REPOSITORY SETUP
# ============================================================================
print_header "GIT REPOSITORY SETUP"

print_step "Creating /allah directory..."
mkdir -p /allah

print_step "Setting anonymous Git identity..."
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"

print_step "Cloning blue repository..."
cd /allah
if [ -d "/allah/blue" ]; then
    print_info "Repository already exists, pulling latest..."
    cd /allah/blue && git pull
else
    git clone https://github.com/rainfrog123/blue.git
fi

print_success "Repository ready at /allah/blue"

# ============================================================================
# SSH HARDENING
# ============================================================================
print_header "SSH SECURITY CONFIGURATION"

print_step "Enabling root login via SSH..."
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

print_step "Disabling password authentication (key-only)..."
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

print_step "Creating drop-in config for Ubuntu 24.04 compatibility..."
mkdir -p /etc/ssh/sshd_config.d/
echo -e "PermitRootLogin yes\nPasswordAuthentication no" | tee /etc/ssh/sshd_config.d/99-custom.conf > /dev/null

print_step "Restarting SSH service..."
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh

print_success "SSH hardened: root login enabled, password auth disabled"

# ============================================================================
# ROOT SSH KEY SETUP
# ============================================================================
print_header "ROOT SSH KEY CONFIGURATION"

print_step "Creating SSH directory structure..."
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys

print_step "Setting secure permissions..."
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

print_step "Adding authorized SSH key..."
# Add key only if not already present
KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey"
grep -qF "jeffrey" /root/.ssh/authorized_keys || echo "$KEY" >> /root/.ssh/authorized_keys

print_success "SSH key added for user 'jeffrey'"

# ============================================================================
# SHELL CONFIGURATION
# ============================================================================
print_header "SHELL CONFIGURATION"

print_step "Linking custom bashrc..."
rm -f /root/.bashrc
ln -sf /allah/blue/linux/extra/shell/bashrc /root/.bashrc

print_success "Custom bashrc linked"

# ============================================================================
# FIREWALL (UFW) - Optional for DO
# ============================================================================
print_header "FIREWALL CONFIGURATION"

print_step "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp      # SSH
ufw allow 12033/tcp   # Shadowsocks
ufw allow 12033/udp   # Shadowsocks UDP
ufw --force enable

print_success "UFW enabled: SSH(22), Shadowsocks(12033)"

# ============================================================================
# COMPLETE
# ============================================================================
print_header "SETUP COMPLETE"

echo ""
print_success "All configurations applied successfully!"
echo ""
print_info "DigitalOcean Premium Intel (4 vCPU, 8GB RAM, 240GB)"
print_info ""
print_info "Summary:"
print_info "  • Hostname: $(hostname)"
print_info "  • Shadowsocks: port 12033 (chacha20-ietf-poly1305)"
print_info "  • TCP BBR: enabled"
print_info "  • SSH: root login enabled, password auth disabled"
print_info "  • Repository: /allah/blue"
print_info "  • Firewall: UFW enabled"
echo ""
echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
sleep 5

reboot
