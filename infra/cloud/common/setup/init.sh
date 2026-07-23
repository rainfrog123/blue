#!/usr/bin/env bash
# Shared VPS bootstrap for digi / ali / azure.
# Usage:
#   bash infra/cloud/common/setup/init.sh digi|ali|azure
#   bash infra/cloud/providers/digitalocean/init.sh   # thin → digi
#   bash infra/cloud/providers/alibaba/init.sh        # thin → ali
#   bash infra/cloud/providers/azure/init.sh          # thin → azure
#
# Env overrides:
#   SKIP_PROXIES=1  SKIP_REBOOT=1  SKIP_SWAP=1  FORCE_SWAP=1
#   SWAP_FILE=…  SWAP_SIZE_GB=…  EXTRA_APT_PACKAGES=…  ENABLE_DHCP6=1
set -euo pipefail

HOST="${1:-${CLOUD_HOST:-}}"
if [[ -z "$HOST" ]]; then
  if grep -qi microsoft /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    HOST=azure
  elif grep -qi alibaba /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    HOST=ali
  elif grep -qi digitalocean /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    HOST=digi
  fi
fi
if [[ -z "$HOST" || ! "$HOST" =~ ^(digi|ali|azure)$ ]]; then
  echo "usage: $0 digi|ali|azure" >&2
  echo "  (or set CLOUD_HOST=digi|ali|azure)" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLUE="${BLUE:-}"
if [[ -z "$BLUE" ]]; then
  if [[ -d /allah/blue/infra/cloud/common/stacks ]]; then
    BLUE=/allah/blue
  elif [[ -d "$HERE/../../stacks" ]]; then
    BLUE="$(cd "$HERE/../../../.." && pwd)"
  fi
fi

SSH_PUBKEY='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5yrqQ9Eq4di8Aalzv0OZLU8LBPXwm2CjSDl3e4LDFQK16M5baWxZb4cd5YytRJBcal28nWiZiYKcJjW7sNUuU5gmij9fBWgvX2r4Rhm7vvt8K5a1gJkcfermkJnfnImBrWHiMfOigpcfFvblYlEcXgvrIKfMeZMJ3PxRfkHEXST2PfS/nqJKZEYB6Du32Nr3LsXisJ4WLJ2la8q7Zj0kM3QW9AeBNgFLKgsez4Y8KWrlQotbgUBkxZm7vUq0aRvFBtIN24DzCjWEm9jMn6UE4d1Bad/fwqdji8cjDcINb9TN8h0oNqG2skP7jOC8tHDMhlRiP90ZtrTBamfp6lldmMQgIAY+CWxRru4Dbbtjn9ikwlcWlyRJN1PwnAbmbYzGaE/rQ7ohwNiH1b7f+znIPayFkm56yYodFjKush6/S16v5P9bgNNIrWMQ08FLYms8PeLxCXz6ZGH6bET6mvkN8Tg4GA7DlzdbaBnCBRxbaIAmA89svFk7fa/tJT8KEBsU= jeffrey'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE_C='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
  echo ""
  echo -e "${BLUE_C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}  $1${NC}"
  echo -e "${BLUE_C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}
print_step()    { echo -e "${YELLOW}▶${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_info()    { echo -e "${CYAN}ℹ${NC} $1"; }
print_warn()    { echo -e "${YELLOW}⚠${NC} $1"; }

run() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

TOTAL_RAM_MB="$(free -m | awk '/^Mem:/{print $2}')"
SWAP_FILE="${SWAP_FILE:-/swapfile}"
SWAP_SIZE_GB="${SWAP_SIZE_GB:-2}"
if [[ "$HOST" == "digi" && "$SWAP_FILE" == "/swapfile" ]]; then
  SWAP_FILE=/digi/swapfile
  SWAP_SIZE_GB="${SWAP_SIZE_GB:-4}"
fi

print_header "INIT  host=$HOST  ram=${TOTAL_RAM_MB}MB"

# --- apt ---
print_header "SYSTEM UPDATE & PACKAGES"
print_step "apt update / upgrade..."
run apt update
run apt upgrade -y

print_step "Installing Docker, Git, utilities..."
if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
  run apt install -y docker.io docker-compose-v2 git tmux htop curl wget iproute2
else
  run apt install -y docker.io docker-compose git tmux htop curl wget iproute2
fi
run apt install -y x11-apps 2>/dev/null || true
if [[ -n "${EXTRA_APT_PACKAGES:-}" ]]; then
  # shellcheck disable=SC2086
  run apt install -y ${EXTRA_APT_PACKAGES}
fi
print_success "Packages installed"

print_step "Enabling Docker..."
run systemctl enable docker
run systemctl start docker
print_success "Docker running"

# --- hostname ---
print_header "HOSTNAME"
print_step "Setting hostname to blue..."
if [[ -f /etc/cloud/cloud.cfg ]]; then
  grep -q 'preserve_hostname' /etc/cloud/cloud.cfg 2>/dev/null || \
    echo 'preserve_hostname: true' | run tee -a /etc/cloud/cloud.cfg >/dev/null
fi
run hostnamectl set-hostname --static blue 2>/dev/null \
  || run hostnamectl set-hostname blue
print_success "Hostname: $(hostname)"

# --- swap ---
print_header "SWAP"
if [[ "${SKIP_SWAP:-0}" == "1" ]]; then
  print_info "SKIP_SWAP=1"
elif [[ "$HOST" != "digi" && "$TOTAL_RAM_MB" -ge 1500 && -z "${FORCE_SWAP:-}" ]]; then
  print_info "Sufficient RAM — skipping swap (set FORCE_SWAP=1 to force)"
else
  run mkdir -p "$(dirname "$SWAP_FILE")"
  if swapon --show 2>/dev/null | grep -qF "$SWAP_FILE"; then
    print_info "Swap already active at $SWAP_FILE"
  else
    if [[ ! -f "$SWAP_FILE" ]]; then
      print_step "Creating ${SWAP_SIZE_GB}G swap at $SWAP_FILE..."
      run fallocate -l "${SWAP_SIZE_GB}G" "$SWAP_FILE"
      run chmod 600 "$SWAP_FILE"
      run mkswap "$SWAP_FILE"
    fi
    run swapon "$SWAP_FILE"
  fi
  if ! grep -qF "$SWAP_FILE none swap sw 0 0" /etc/fstab 2>/dev/null; then
    echo "$SWAP_FILE none swap sw 0 0" | run tee -a /etc/fstab >/dev/null
  fi
  print_success "Swap ready at $SWAP_FILE"
fi

# --- azure root unlock ---
if [[ "$HOST" == "azure" ]]; then
  print_header "AZURE ROOT UNLOCK"
  echo "root:$(openssl rand -base64 32)" | run chpasswd
  print_success "Root password randomized (SSH key auth still required)"
fi

# --- git ---
print_header "GIT /allah/blue"
run mkdir -p /allah
git config --global user.name "$(openssl rand -hex 12)" || true
git config --global user.email "$(openssl rand -hex 12)@example.com" || true
if [[ -d /allah/blue/.git ]]; then
  print_step "Pulling existing /allah/blue..."
  git -C /allah/blue pull --ff-only || print_warn "git pull failed — continuing"
else
  print_step "Cloning blue..."
  git -C /allah clone https://github.com/rainfrog123/blue.git
fi
BLUE=/allah/blue
print_success "Repository at $BLUE"

# --- BBR ---
print_header "TCP BBR & NETWORK"
print_step "Loading BBR..."
run modprobe tcp_bbr || true
print_step "Writing sysctl tuning..."
run tee /etc/sysctl.d/99-network-tuning.conf >/dev/null <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5
EOF
run sysctl --system >/dev/null || run sysctl -p || true

print_step "Primary NIC qdisc = fq..."
run tee /usr/local/sbin/set-nic-fq.sh >/dev/null <<'SCRIPT'
#!/bin/bash
NIC="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
NIC="${NIC:-eth0}"
/sbin/tc qdisc replace dev "$NIC" root fq 2>/dev/null || true
SCRIPT
run chmod +x /usr/local/sbin/set-nic-fq.sh
run /usr/local/sbin/set-nic-fq.sh || true
run tee /etc/systemd/system/eth0-fq.service >/dev/null <<'EOF'
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
run systemctl daemon-reload
run systemctl enable --now eth0-fq.service 2>/dev/null || true
print_success "BBR + fq enabled"

# --- dhcp6 (ali by default) ---
if [[ "$HOST" == "ali" || "${ENABLE_DHCP6:-}" == "1" ]]; then
  print_header "IPv6 NETPLAN"
  if ls /etc/netplan/*.yaml >/dev/null 2>&1; then
    for f in /etc/netplan/*.yaml; do
      if grep -qE 'eth[0-9]|ens[0-9]' "$f" && ! grep -q 'dhcp6:' "$f"; then
        run sed -i '/dhcp4:\s*true/a\            dhcp6: true' "$f" || true
      fi
    done
    run netplan apply || true
    print_success "dhcp6 attempted"
  else
    print_info "No netplan YAML — skip dhcp6"
  fi
fi

# --- SSH ---
print_header "SSH HARDENING"
run sed -i 's/^#*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
run sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
run mkdir -p /etc/ssh/sshd_config.d/
echo -e "PermitRootLogin yes\nPasswordAuthentication no" | run tee /etc/ssh/sshd_config.d/99-custom.conf >/dev/null
run systemctl daemon-reload
run systemctl restart ssh.socket 2>/dev/null || true
run systemctl restart ssh 2>/dev/null || run systemctl restart sshd 2>/dev/null || true
print_success "SSH: root yes, password auth no"

print_header "ROOT SSH KEY"
run mkdir -p /root/.ssh
run touch /root/.ssh/authorized_keys
run chmod 700 /root/.ssh
run chmod 600 /root/.ssh/authorized_keys
run sed -i '/command="echo '\''Please login as the user/d' /root/.ssh/authorized_keys 2>/dev/null || true
run sed -i '/no-port-forwarding,no-agent-forwarding/d' /root/.ssh/authorized_keys 2>/dev/null || true
grep -qF "jeffrey" /root/.ssh/authorized_keys 2>/dev/null \
  || echo "$SSH_PUBKEY" | run tee -a /root/.ssh/authorized_keys >/dev/null
print_success "Authorized key present"

# --- bashrc ---
print_header "SHELL"
if [[ -f "$BLUE/infra/dotfiles/shell/bashrc" ]]; then
  run rm -f /root/.bashrc
  run ln -sf "$BLUE/infra/dotfiles/shell/bashrc" /root/.bashrc
  print_success "bashrc linked"
else
  print_warn "bashrc not found — skip"
fi

# --- proxies ---
print_header "SHARED PROXY STACKS"
if [[ "${SKIP_PROXIES:-0}" == "1" ]]; then
  print_info "SKIP_PROXIES=1"
else
  print_step "up-all.sh $HOST..."
  run mkdir -p "$BLUE/infra/cloud/hosts/$HOST/hysteria/acme"
  if [[ ! -f "$BLUE/infra/cloud/hosts/$HOST/cloudflared/site.env" \
     && ! -f "$BLUE/infra/cloud/hosts/$HOST/cloudflared/.env" ]]; then
    print_info "No cloudflared site.env yet — tunnel stacks may be skipped"
  fi
  bash "$BLUE/infra/cloud/common/stacks/up-all.sh" "$HOST" \
    || print_warn "up-all reported issues — check hosts/$HOST/ site files"
  print_success "Proxy bring-up attempted"
fi

# --- cleanup ---
print_header "CLEANUP"
run apt autoremove -y || true
run apt clean || true

print_header "SETUP COMPLETE"
print_success "host=$HOST"
print_info "  • Hostname: blue"
print_info "  • Stacks: common/stacks + hosts/$HOST"
print_info "  • Repo: $BLUE"
print_info "  • BBR + fq: enabled"

if [[ "${SKIP_REBOOT:-0}" == "1" ]]; then
  print_info "SKIP_REBOOT=1 — not rebooting"
else
  echo -e "${YELLOW}Rebooting in 5 seconds...${NC}"
  sleep 5
  run reboot
fi
