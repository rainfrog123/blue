#!/bin/bash

set -e  # Exit on error

# Update and upgrade system
sudo apt update && sudo apt upgrade -y
# sudo apt install -y zsh
# echo 'PROMPT="%~ $ "' >> ~/.zshrc
# Install Docker and Docker Compose
sudo apt install -y docker.io docker-compose
sudo apt install -y tmux htop x11-apps
echo 'preserve_hostname: true' | sudo tee -a /etc/cloud/cloud.cfg
sudo hostnamectl set-hostname --static blue
# Pull the shadowsocks-r image
sudo docker pull teddysun/shadowsocks-r

# Create the shadowsocks-r configuration file
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

# Run the shadowsocks-r Docker container
sudo docker run -d -p 19000:19000 -p 19000:19000/udp --name ssr --restart=always -v /etc/shadowsocks-r:/etc/shadowsocks-r teddysun/shadowsocks-r

# Add BBR settings to sysctl.conf
echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf

# Apply sysctl settings
sudo sysctl -p

# Set PS1 prompt in ~/.bashrc
echo 'PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "' >> ~/.bashrc

# Create a directory /allah
sudo mkdir /allah

# Set random global username and email for Git
git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"

# Change to /allah and clone a GitHub repository
cd /allah
git clone https://github.com/rainfrog123/blue.git

# ✅ Enable root login via SSH
sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

# 🔒 Disable password authentication (only allow SSH key login)
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 🚀 Restart SSH service to apply changes
sudo systemctl restart sshd


# Create SSH directory and file for root if they don't exist
sudo mkdir -p /root/.ssh
sudo touch /root/.ssh/authorized_keys

# Set permissions to ensure security
sudo chmod 700 /root/.ssh
sudo chmod 600 /root/.ssh/authorized_keys
sudo sed -i '/command="echo '\''Please login as the user \\"admin\\" rather than the user \\"root\\".'\''/d' /root/.ssh/authorized_keys

# Add the public SSH key to root's authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey" | sudo tee -a /root/.ssh/authorized_keys > /dev/null

sudo rm /root/.bashrc
sudo ln -sf /allah/blue/linux/extra/bashrc ~/.bashrc

# Notify user of script completion
echo "Root login enabled and SSH key added successfully."
sudo reboot  