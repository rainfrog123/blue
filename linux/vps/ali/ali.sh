#!/bin/bash

# Skip errors and continue execution
set +e

# ============================================================================
# SYSTEM SETUP AND DEPENDENCIES
# ============================================================================

echo ">>> Installing system packages..."
sudo apt update && sudo apt upgrade -y || echo "Warning: apt update/upgrade failed, continuing..."
sudo apt install -y docker.io docker-compose || echo "Warning: docker installation failed, continuing..."
sudo apt install -y tmux htop x11-apps || echo "Warning: utility packages installation failed, continuing..."

# ============================================================================
# SHADOWSOCKS-R CONFIGURATION
# ============================================================================

echo ">>> Configuring Shadowsocks-R..."
sudo docker pull teddysun/shadowsocks-r || echo "Warning: docker pull failed, continuing..."

sudo mkdir -p /etc/shadowsocks-r/ || true
sudo bash -c 'cat > /etc/shadowsocks-r/config.json <<EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":19000,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"bxsnucrgk6hfish",
    "timeout":120,
    "method":"chacha20-ietf",
    "protocol":"auth_aes128_sha1",
    "protocol_param":"",
    "obfs":"plain",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":true,
    "workers":5
}
EOF' || echo "Warning: shadowsocks config creation failed, continuing..."

# Run the shadowsocks-r Docker container
sudo docker rm -f ssr 2>/dev/null || true
sudo docker run -d -p 19000:19000 -p 19000:19000/udp --name ssr --restart=always -v /etc/shadowsocks-r:/etc/shadowsocks-r teddysun/shadowsocks-r || echo "Warning: docker run failed, continuing..."

# Add BBR settings to sysctl.conf (check if already exists)
echo ">>> Configuring BBR..."
grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf || echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf || true
grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf || true

# Apply sysctl settings
sudo sysctl -p || echo "Warning: sysctl -p failed, continuing..."

# ============================================================================
# HOSTNAME CONFIGURATION
# ============================================================================

echo ">>> Setting hostname..."
sudo hostnamectl set-hostname blue || true
echo "blue" | sudo tee /etc/hostname || true
sudo sed -i 's/127.0.1.1.*/127.0.1.1\tblue/' /etc/hosts || true

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

echo ">>> Configuring environment..."
# Set PS1 prompt in ~/.bashrc
echo 'PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "' >> ~/.bashrc || true

# Create a directory /allah
sudo mkdir -p /allah || true

# Set random global username and email for Git
git config --global user.name "$(openssl rand -hex 12)" || true
git config --global user.email "$(openssl rand -hex 12)@example.com" || true

# Change to /allah and clone a GitHub repository
cd /allah || true
git clone https://github.com/rainfrog123/blue.git || echo "Warning: git clone failed (may already exist), continuing..."

# ============================================================================
# SSH ACCESS CONFIGURATION
# ============================================================================

echo ">>> Configuring SSH access..."
# Enable root login by modifying sshd_config (handles commented lines too)
if grep -q "^#*PermitRootLogin" /etc/ssh/sshd_config; then
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
else
    echo "PermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config || true
fi

# Also add to sshd_config.d for newer Ubuntu versions
sudo mkdir -p /etc/ssh/sshd_config.d || true
echo "PermitRootLogin yes" | sudo tee /etc/ssh/sshd_config.d/99-permit-root.conf || true

# Restart SSH service to apply changes (ssh for Ubuntu, sshd for other distros)
sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true

# Create SSH directory and file for root if they don't exist
sudo mkdir -p /root/.ssh || true
sudo touch /root/.ssh/authorized_keys || true

# Set permissions to ensure security
sudo chmod 700 /root/.ssh || true
sudo chmod 600 /root/.ssh/authorized_keys || true

# Add the public SSH key to root's authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" | sudo tee -a /root/.ssh/authorized_keys > /dev/null || true

# ============================================================================
# FINAL SETUP
# ============================================================================

echo ">>> Final setup..."
# Replace default bashrc with custom one
sudo rm -f /root/.bashrc || true
sudo ln -sf /allah/blue/linux/extra/bashrc /root/.bashrc || true

# Notify user of script completion
echo ""
echo "============================================"
echo "Alibaba Cloud VPS setup completed!"
echo "============================================"
echo "- Shadowsocks-R configured on port 19000"
echo "- Root SSH access enabled"
echo "- Custom bashrc linked"
echo "- BBR congestion control enabled"
echo "- Hostname changed to 'blue'"
echo ""
echo "Note: Some steps may have been skipped due to errors."
echo ""
echo "System will restart in 5 seconds..."
sleep 5
sudo reboot
