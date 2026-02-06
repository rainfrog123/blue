#!/bin/bash
#
# VPS Initial Setup Script
# Configures a fresh Ubuntu server with Docker, Shadowsocks, BBR, and SSH hardening
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

print_step "Installing utilities (tmux, htop, x11-apps)..."
sudo apt install -y tmux htop x11-apps

print_success "All packages installed"

# ============================================================================
# HOSTNAME CONFIGURATION
# ============================================================================
print_header "HOSTNAME CONFIGURATION"

print_step "Setting hostname to 'blue'..."
echo 'preserve_hostname: true' | sudo tee -a /etc/cloud/cloud.cfg > /dev/null
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
# TCP BBR CONGESTION CONTROL
# ============================================================================
print_header "TCP BBR OPTIMIZATION"

print_step "Loading BBR kernel module..."
sudo touch /etc/sysctl.conf
sudo modprobe tcp_bbr

print_step "Configuring BBR settings..."
echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf > /dev/null

print_step "Applying sysctl settings..."
sudo sysctl -p

print_success "BBR congestion control enabled"

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
sudo systemctl restart ssh.socket
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

print_step "Removing cloud provider login restrictions..."
sudo sed -i '/command="echo '\''Please login as the user \\"admin\\" rather than the user \\"root\\".'\''/d' /root/.ssh/authorized_keys

print_step "Adding authorized SSH key..."
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" | sudo tee -a /root/.ssh/authorized_keys > /dev/null

print_success "SSH key added for user 'jeffrey'"

# ============================================================================
# SHELL CONFIGURATION
# ============================================================================
print_header "SHELL CONFIGURATION"

print_step "Linking custom bashrc..."
sudo rm -f /root/.bashrc
sudo ln -sf /allah/blue/linux/extra/shell/bashrc ~/.bashrc

print_success "Custom bashrc linked"

# ============================================================================
# COMPLETE
# ============================================================================
print_header "SETUP COMPLETE"

echo ""
print_success "All configurations applied successfully!"
echo ""
print_info "Summary:"
print_info "  • Hostname: blue"
print_info "  • Shadowsocks: port 12033 (chacha20-ietf-poly1305)"
print_info "  • TCP BBR: enabled"
print_info "  • SSH: root login enabled, password auth disabled"
print_info "  • Repository: /allah/blue"
echo ""
echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
sleep 5

sudo reboot
