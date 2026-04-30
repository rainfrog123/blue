#!/bin/bash

# SSR Deployment Script
# Author: Claude
# Date: 2025-03-12
# Description: Script to connect to server, enable root login, and deploy SSR

set -e
echo "Starting SSR deployment script..."

# Server details
SERVER_IP="35.187.195.55"
SSH_USER="jeffrey"
ROOT_USER="root"
ROOT_PASS="4dwlq5!H4uA26A8"

# Current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if SSH key exists
if [ ! -f "${SCRIPT_DIR}/id_rsa" ]; then
    echo "Error: SSH key not found in the project directory"
    exit 1
fi

# Set proper permissions for SSH key
chmod 600 "${SCRIPT_DIR}/id_rsa"

echo "Step 1: Connecting to server and enabling root login..."
ssh -i "${SCRIPT_DIR}/id_rsa" -o StrictHostKeyChecking=accept-new $SSH_USER@$SERVER_IP << 'EOF'
    echo "Connected as jeffrey, enabling root login..."
    
    # Create root .ssh directory if it doesn't exist
    sudo mkdir -p /root/.ssh
    
    # Set proper permissions
    sudo chmod 700 /root/.ssh
    
    # Create authorized_keys file for root if it doesn't exist
    sudo touch /root/.ssh/authorized_keys
    
    # Set proper permissions for authorized_keys
    sudo chmod 600 /root/.ssh/authorized_keys
    
    # Copy our public key to root's authorized_keys
    cat ~/.ssh/authorized_keys | sudo tee /root/.ssh/authorized_keys > /dev/null
    
    # Update sshd_config to allow root login with key
    sudo sed -i 's/PermitRootLogin no/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
    sudo sed -i 's/PermitRootLogin without-password/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
    
    # Restart SSH service
    sudo systemctl restart sshd
    
    echo "Root login enabled successfully!"
EOF

echo "Step 2: Waiting for SSH service to restart..."
sleep 5

echo "Step 3: Connecting as root and deploying SSR..."
ssh -i "${SCRIPT_DIR}/id_rsa" -o StrictHostKeyChecking=accept-new $ROOT_USER@$SERVER_IP << 'EOF'
    echo "Connected as root, deploying SSR..."
    
    # Create setup script - Using the exact same script from deploy_nodes.py
    cat > /root/setup.sh << 'SETUPEOF'
#!/bin/bash
set -e
LOG_FILE="/var/log/setup_script.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log "Starting automated setup..."
export DEBIAN_FRONTEND=noninteractive
sudo apt update -y && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose tmux htop x11-apps
sudo docker pull teddysun/shadowsocks-r
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
sudo docker run -d -p 19000:19000 -p 19000:19000/udp --name ssr --restart=always -v /etc/shadowsocks-r:/etc/shadowsocks-r teddysun/shadowsocks-r
echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
echo 'PS1="\\[\\033[1;32m\\]\\u\\[\\033[0m\\]@\\[\\033[1;34m\\]\\h\\[\\033[0m\\] \\[\\e[1;34m\\]\\w\\[\\e[0m\\] 🚀🚀🚀  $ "' >> ~/.bashrc
sudo mkdir -p /allah
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"
cd /allah
git clone https://github.com/rainfrog123/stuff.git
mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys
if ! grep -q "jeffrey" ~/.ssh/authorized_keys; then
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" >> ~/.ssh/authorized_keys
    chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
fi
log "Setup completed successfully!"
SETUPEOF

    # Make setup script executable
    chmod +x /root/setup.sh
    
    # Run setup script
    echo "Running SSR setup script..."
    /root/setup.sh
    
    # Check if Docker container is running
    if docker ps | grep -q "teddysun/shadowsocks-r"; then
        echo "✅ SSR container is running successfully"
        echo "SSR server details:"
        echo "IP: $(hostname -I | awk '{print $1}')"
        echo "Port: 19000"
        echo "Password: bxsnucrgk6hfish"
        echo "Method: chacha20-ietf"
        echo "Protocol: auth_aes128_sha1"
    else
        echo "❌ SSR container failed to start"
    fi
EOF

echo "SSR deployment completed!"
echo "✅ SSR server should now be running at $SERVER_IP:19000"
echo "Password: bxsnucrgk6hfish"
echo "Method: chacha20-ietf"
echo "Protocol: auth_aes128_sha1" 