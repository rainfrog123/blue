#!/bin/bash

set -e

# ==============================================================================
# Vultr VPS Setup Script for Debian 13.3 (Trixie)
# Tested on: Debian 13.3, Kernel 6.12.63+deb13-amd64
# ==============================================================================

# ==============================================================================
# SYSTEM SETUP AND DEPENDENCIES
# ==============================================================================

apt update && apt upgrade -y

apt install -y \
    docker.io \
    docker-compose \
    tmux \
    htop \
    x11-apps \
    git \
    curl \
    openssh-server

# ==============================================================================
# SHADOWSOCKS-R CONFIGURATION
# ==============================================================================

docker pull teddysun/shadowsocks-r

mkdir -p /etc/shadowsocks-r
cat > /etc/shadowsocks-r/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_ipv6": "::",
    "server_port": 19000,
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "bxsnucrgk6hfish",
    "timeout": 120,
    "method": "chacha20-ietf",
    "protocol": "auth_aes128_sha1",
    "protocol_param": "",
    "obfs": "plain",
    "obfs_param": "",
    "redirect": "",
    "dns_ipv6": false,
    "fast_open": true,
    "workers": 5
}
EOF

docker run -d \
    -p 19000:19000 \
    -p 19000:19000/udp \
    --name ssr \
    --restart=always \
    -v /etc/shadowsocks-r:/etc/shadowsocks-r \
    teddysun/shadowsocks-r

# ==============================================================================
# BBR CONGESTION CONTROL
# ==============================================================================

cat >> /etc/sysctl.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p

# ==============================================================================
# ENVIRONMENT CONFIGURATION
# ==============================================================================

hostnamectl set-hostname blue

echo 'PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "' >> ~/.bashrc

mkdir -p /allah

git config --global user.name "$(openssl rand -hex 12)"
git config --global user.email "$(openssl rand -hex 12)@example.com"

cd /allah
git clone https://github.com/rainfrog123/blue.git

# ==============================================================================
# SSH ACCESS CONFIGURATION
# ==============================================================================

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

systemctl restart ssh

mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

cat >> /root/.ssh/authorized_keys <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey
EOF

# ==============================================================================
# FINAL SETUP
# ==============================================================================

rm -f /root/.bashrc
ln -sf /allah/blue/linux/extra/bashrc /root/.bashrc

cat <<EOF
================================================================================
Vultr VPS setup completed successfully!
================================================================================
OS: Debian 13.3 (Trixie)

  • Shadowsocks-R configured on port 19000
  • Root SSH access enabled
  • Custom bashrc linked
  • BBR congestion control enabled
  • Hostname set to blue

================================================================================
EOF

sudo reboot
