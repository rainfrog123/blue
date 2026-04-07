#!/bin/bash
#
# Universal VPS Setup Script
# Configures a fresh Ubuntu server with Docker, Shadowsocks, BBR, and SSH hardening
# Works across: Azure, Alibaba, DigitalOcean, AWS, etc.
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

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# ============================================================================
# CLOUD PROVIDER DETECTION
# ============================================================================
print_header "DETECTING ENVIRONMENT"

CLOUD_PROVIDER="unknown"
if grep -qi microsoft /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    CLOUD_PROVIDER="azure"
elif grep -qi alibaba /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    CLOUD_PROVIDER="alibaba"
elif grep -qi digitalocean /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    CLOUD_PROVIDER="digitalocean"
elif grep -qi amazon /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    CLOUD_PROVIDER="aws"
fi

TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
print_info "Cloud provider: ${CLOUD_PROVIDER}"
print_info "Total RAM: ${TOTAL_RAM_MB} MB"

# ============================================================================
# SWAP SETUP (for low-memory systems)
# ============================================================================
if [ "$TOTAL_RAM_MB" -lt 1500 ]; then
    print_header "SWAP CONFIGURATION"
    
    if [ ! -f /swapfile ]; then
        print_step "Creating 2GB swap file (low RAM detected)..."
        sudo fallocate -l 2G /swapfile
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
        print_success "2GB swap file created and enabled"
    else
        print_info "Swap file already exists"
    fi
else
    print_info "Sufficient RAM, skipping swap setup"
fi

# ============================================================================
# SYSTEM UPDATE
# ============================================================================
print_header "SYSTEM UPDATE & UPGRADE"

print_step "Updating package lists..."
sudo apt update

print_step "Upgrading installed packages..."
sudo apt upgrade -y

print_success "System updated successfully"

# ============================================================================
# PACKAGE INSTALLATION
# ============================================================================
print_header "INSTALLING PACKAGES"

print_step "Installing Docker, Docker Compose, and Git..."
sudo apt install -y docker.io docker-compose git

print_step "Installing utilities (tmux, htop)..."
sudo apt install -y tmux htop

print_success "All packages installed"

# ============================================================================
# HOSTNAME CONFIGURATION
# ============================================================================
print_header "HOSTNAME CONFIGURATION"

print_step "Setting hostname to 'blue'..."
if [ -f /etc/cloud/cloud.cfg ]; then
    grep -q 'preserve_hostname' /etc/cloud/cloud.cfg || \
        echo 'preserve_hostname: true' | sudo tee -a /etc/cloud/cloud.cfg > /dev/null
fi
sudo hostnamectl set-hostname --static blue

print_success "Hostname set to 'blue'"

# ============================================================================
# SHADOWSOCKS-RUST SETUP
# ============================================================================
print_header "SHADOWSOCKS-RUST PROXY SERVER"

print_step "Pulling shadowsocks-rust Docker image..."
sudo docker pull teddysun/shadowsocks-rust

print_step "Creating configuration directory..."
sudo mkdir -p /etc/shadowsocks-rust/

print_step "Writing configuration file..."
sudo bash -c 'cat > /etc/shadowsocks-rust/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": 12033,
    "password": "bxsnucrgk6hfish",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "mode": "tcp_and_udp",
    "fast_open": true
}
EOF'

print_step "Starting shadowsocks-rust container..."
sudo docker run -d \
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
sudo modprobe tcp_bbr

print_step "Configuring network optimizations..."
sudo tee /etc/sysctl.d/99-network-tuning.conf > /dev/null <<EOF
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

# Improve handling of short-lived connections
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

# VM memory tuning (for low-RAM systems)
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5
EOF

print_step "Applying sysctl settings..."
sudo sysctl --system

print_success "BBR and network optimizations enabled"
print_info "Buffer sizes: 16MB max | TCP Fast Open: bidirectional"

# ============================================================================
# GIT REPOSITORY SETUP
# ============================================================================
print_header "GIT REPOSITORY SETUP"

print_step "Creating /allah directory..."
sudo mkdir -p /allah

print_step "Setting anonymous Git identity..."
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"

print_step "Cloning blue repository..."
cd /allah
git clone https://github.com/rainfrog123/blue.git

print_success "Repository cloned to /allah/blue"

# ============================================================================
# SSH HARDENING
# ============================================================================
print_header "SSH SECURITY CONFIGURATION"

print_step "Enabling root login via SSH..."
sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

print_step "Disabling password authentication (key-only)..."
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

print_step "Creating drop-in config for Ubuntu 24.04 compatibility..."
sudo mkdir -p /etc/ssh/sshd_config.d/
echo -e "PermitRootLogin yes\nPasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/99-custom.conf > /dev/null

print_step "Restarting SSH service..."
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket 2>/dev/null || true
sudo systemctl restart ssh

print_success "SSH hardened: root login enabled, password auth disabled"

# ============================================================================
# ROOT SSH KEY SETUP
# ============================================================================
print_header "ROOT SSH KEY CONFIGURATION"

print_step "Creating SSH directory structure..."
sudo mkdir -p /root/.ssh
sudo touch /root/.ssh/authorized_keys

print_step "Setting secure permissions..."
sudo chmod 700 /root/.ssh
sudo chmod 600 /root/.ssh/authorized_keys

# Azure and some providers lock the root account
print_step "Unlocking root account..."
echo "root:$(openssl rand -base64 32)" | sudo chpasswd

print_step "Removing cloud provider login restrictions..."
# Azure/AWS style restrictions
sudo sed -i '/command="echo '\''Please login as the user/d' /root/.ssh/authorized_keys
# DigitalOcean style restrictions  
sudo sed -i '/no-port-forwarding,no-agent-forwarding/d' /root/.ssh/authorized_keys

print_step "Adding authorized SSH key..."
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" | sudo tee -a /root/.ssh/authorized_keys > /dev/null

print_success "SSH key added for user 'jeffrey'"

# ============================================================================
# SHELL CONFIGURATION
# ============================================================================
print_header "SHELL CONFIGURATION"

print_step "Linking custom bashrc..."
sudo rm -f /root/.bashrc
sudo ln -sf /allah/blue/linux/extra/shell/bashrc /root/.bashrc

print_success "Custom bashrc linked"

# ============================================================================
# CLEANUP
# ============================================================================
print_header "CLEANUP"

print_step "Removing unnecessary packages..."
sudo apt autoremove -y

print_step "Cleaning apt cache..."
sudo apt clean

print_success "Cleanup complete"

# ============================================================================
# COMPLETE
# ============================================================================
print_header "SETUP COMPLETE"

echo ""
print_success "All configurations applied successfully!"
echo ""
print_info "Summary:"
print_info "  • Provider: ${CLOUD_PROVIDER}"
print_info "  • Hostname: blue"
print_info "  • Shadowsocks: port 12033 (chacha20-ietf-poly1305)"
print_info "  • TCP BBR: enabled with full network tuning"
print_info "  • SSH: root login enabled, password auth disabled"
print_info "  • Repository: /allah/blue"
[ "$TOTAL_RAM_MB" -lt 1500 ] && print_info "  • Swap: 2GB (low RAM mode)"
echo ""
echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
sleep 5

sudo reboot
