#!/bin/bash
#
# VPS Initial Setup Script
# Configures a fresh Ubuntu server with Docker, Shadowsocks, BBR/fq tweaks, and SSH hardening
#
# Tweaks included: BBR + fq qdisc, tcp_mtu_probing, SS --network host / listen ::,
#                  Hy2 from repo (bandwidth 100 mbps), netplan dhcp6
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

print_step "Installing Docker, Docker Compose plugin, and Git..."
# Ubuntu 26.04+ (Resolute): classic `docker-compose` package is gone; use v2 plugin.
sudo apt install -y docker.io docker-compose-v2 git

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
    "server": "::",
    "server_port": 12033,
    "password": "bxsnucrgk6hfish",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "mode": "tcp_and_udp",
    "fast_open": true
}
EOF'

print_step "Starting shadowsocks-rust container (host network)..."
sudo docker rm -f ss-rust 2>/dev/null || true
sudo docker run -d \
    --name ss-rust \
    --restart=always \
    --network host \
    -v /etc/shadowsocks-rust:/etc/shadowsocks-rust \
    teddysun/shadowsocks-rust

print_success "Shadowsocks-rust running on port 12033 (host network, listen ::)"
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

# MTU probing (path MTU blackholes)
net.ipv4.tcp_mtu_probing = 1
EOF

print_step "Applying sysctl settings..."
sudo sysctl --system

print_step "Setting primary NIC qdisc to fq (persist via systemd)..."
sudo apt install -y iproute2 >/dev/null
sudo tee /usr/local/sbin/set-nic-fq.sh > /dev/null <<'SCRIPT'
#!/bin/bash
NIC="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
NIC="${NIC:-eth0}"
/sbin/tc qdisc replace dev "$NIC" root fq
SCRIPT
sudo chmod +x /usr/local/sbin/set-nic-fq.sh
sudo /usr/local/sbin/set-nic-fq.sh || true
sudo tee /etc/systemd/system/eth0-fq.service > /dev/null <<'EOF'
[Unit]
Description=Set primary NIC qdisc to fq for BBR
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/set-nic-fq.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now eth0-fq.service

print_success "BBR and network optimizations enabled"
print_info "Buffer sizes: 16MB max | TFO | mtu_probing=1 | NIC qdisc=fq"

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
# HYSTERIA2 (from cloned repo)
# ============================================================================
print_header "HYSTERIA2 PROXY SERVER"

print_step "Starting Hysteria2 (host network, :443, bandwidth 100 mbps)..."
sudo mkdir -p /allah/blue/infra/cloud/ali/hysteria/acme
cd /allah/blue/infra/cloud/ali/hysteria
sudo docker compose up -d

print_success "Hysteria2 started (check: docker logs hysteria2)"
print_info "ACME domain must already point at this host (hy.hyas.site)"

# ============================================================================
# IPv6 NETPLAN (dhcp6)
# ============================================================================
print_header "IPv6 NETPLAN"

print_step "Enabling dhcp6 on eth* in netplan (if present)..."
if ls /etc/netplan/*.yaml >/dev/null 2>&1; then
  for f in /etc/netplan/*.yaml; do
    if grep -qE 'eth[0-9]|ens[0-9]' "$f" && ! grep -q 'dhcp6:' "$f"; then
      sudo sed -i '/dhcp4:\s*true/a\            dhcp6: true' "$f" || true
    fi
  done
  sudo netplan apply || true
  print_success "dhcp6 enabled (netplan apply attempted)"
else
  print_info "No netplan YAML found — skip dhcp6"
fi

# ============================================================================
# SSH HARDENING
# ============================================================================
print_header "SSH SECURITY CONFIGURATION"

print_step "Enabling root login via SSH..."
sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

print_step "Disabling password authentication (key-only)..."
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

print_step "Creating drop-in config for Ubuntu 24.04+ / 26.04 compatibility..."
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
sudo ln -sf /allah/blue/infra/dotfiles/shell/bashrc ~/.bashrc

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
print_info "  • Shadowsocks: port 12033 (chacha20-ietf-poly1305, host net, ::)"
print_info "  • Hysteria2: :443 (repo compose, bandwidth 100 mbps)"
print_info "  • TCP BBR + fq qdisc + mtu_probing: enabled"
print_info "  • IPv6: dhcp6 via netplan (if YAML present)"
print_info "  • SSH: root login enabled, password auth disabled"
print_info "  • Repository: /allah/blue"
echo ""
echo -e "${YELLOW}System will reboot in 5 seconds...${NC}"
sleep 5

sudo reboot
