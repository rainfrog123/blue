#!/bin/bash

set -e  # Exit on error
LOG_FILE="/var/log/setup_script.log"

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting automated setup..."

# Prevent prompts during package installation
export DEBIAN_FRONTEND=noninteractive

# Update and upgrade system
log "Updating and upgrading system..."
sudo apt update -y && sudo apt upgrade -y

# Install Docker, Docker Compose, and other utilities
log "Installing required packages..."
sudo apt install -y docker.io docker-compose tmux htop x11-apps

# Pull the Shadowsocks-R image
log "Pulling Shadowsocks-R Docker image..."
sudo docker pull teddysun/shadowsocks-r

# Create Shadowsocks-R configuration
log "Setting up Shadowsocks-R configuration..."
sudo mkdir -p /etc/shadowsocks-r/

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
EOF'

# Run the Shadowsocks-R Docker container
log "Starting Shadowsocks-R container..."
sudo docker run -d -p 19000:19000 -p 19000:19000/udp --name ssr --restart=always -v /etc/shadowsocks-r:/etc/shadowsocks-r teddysun/shadowsocks-r

# Enable TCP BBR for better network performance
log "Enabling TCP BBR..."
echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Set a custom PS1 prompt
log "Setting up custom shell prompt..."
echo 'PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "' >> ~/.bashrc

# Create a directory /allah
log "Creating /allah directory..."
sudo mkdir -p /allah

# Set random global Git username and email
log "Configuring Git with random credentials..."
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"

# Clone repository into /allah
log "Cloning repository into /allah..."
cd /allah
git clone https://github.com/rainfrog123/blue.git

# Configure SSH keys
log "Setting up SSH authorized keys..."
mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys
if ! grep -q "jeffrey" ~/.ssh/authorized_keys; then
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" >> ~/.ssh/authorized_keys
    chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
else
    log "SSH key already exists."
fi

log "Setup completed successfully!"
