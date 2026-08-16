#!/usr/bin/env bash
# Shared VPS bootstrap for digi / ali / azure / ali-jp / oracle-tokyo / oracle-tokyo2 / oracle-a1 / vultr-osk.
# Usage:
#   bash cloud/common/setup/init.sh Digi|Ali|Azure|ali-jp|oracle-tokyo|oracle-tokyo2|oracle-a1|vultr-osk

#   bash cloud/providers/digitalocean/init.sh   # thin → Digi
#   bash cloud/providers/alibaba/init.sh        # thin → Ali
#   bash cloud/providers/azure/init.sh          # thin → Azure
#   bash cloud/providers/Oracle/init.sh         # thin → oracle-tokyo
#   bash cloud/providers/vultr/init.sh          # thin → vultr-osk
#
# Env overrides:
#   SKIP_PROXIES=1  SKIP_REBOOT=1  SKIP_SWAP=1  FORCE_SWAP=1  SKIP_CRON=1
#   SWAP_FILE=…  SWAP_SIZE_GB=…  EXTRA_APT_PACKAGES=…  ENABLE_DHCP6=1
#   LEGACY_PROXIES=1  — bring up old hysteria/ss-rust/xray-* instead of 3x-ui MIGRATE
#   SKIP_BESZEL=1   — skip Beszel agent (default: seed + connect to fleet Hub)
#   SKIP_XUI_SEED=1 — skip auto SS/Hy2/Trojan inbound seed after 3x-ui up
#   INIT_LOG=…      — tee stdout/stderr to this file (Oracle hosts default /var/log/oracle-init.log)
# Default proxies: 3x-ui (SQLite) + cloudflared (hosts/<host>/3x-ui/MIGRATE).
# After up: panel login applied + default inbounds seeded (usable immediately).
# Default monitoring: Beszel agent → https://beszel.hyas.site
# Default cron: root daily reboot 07:00 Asia/Singapore (SKIP_CRON=1 to skip)
# Ubuntu vixie cron schedules in system local time (CRON_TZ is not used for scheduling).
# Oracle hosts: live log → sudo tail -f /var/log/oracle-init.log
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

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
if [[ -z "$HOST" ]]; then
  echo "usage: $0 <host>   # Digi|Ali|Azure|ali-jp|oracle-tokyo|..." >&2
  echo "  (or set CLOUD_HOST=...)" >&2
  exit 2
fi
# shellcheck source=../lib/normalize-host.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/normalize-host.sh"
HOST="$(normalize_cloud_host "$HOST")"

# Live log for Oracle micros (and INIT_LOG=… for any host)
if [[ -z "${INIT_LOG:-}" && "$HOST" == oracle-* ]]; then
  INIT_LOG=/var/log/oracle-init.log
fi
if [[ -n "${INIT_LOG:-}" ]]; then
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    touch "$INIT_LOG"
    chmod 644 "$INIT_LOG" || true
  else
    sudo touch "$INIT_LOG"
    sudo chmod 644 "$INIT_LOG" || true
    sudo chown root:root "$INIT_LOG" || true
  fi
  # Append with timestamps; keep console + file (tail -f friendly)
  exec > >(tee -a "$INIT_LOG") 2>&1
  echo ""
  echo "===== init host=$HOST $(date -u +%Y-%m-%dT%H:%M:%SZ) pid=$$ INIT_LOG=$INIT_LOG ====="
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_ROOT="$(cd "$HERE/../../hosts" && pwd)"
if [[ ! -d "$HOSTS_ROOT/$HOST" ]]; then
  echo "unknown host '$HOST' (no cloud/hosts/$HOST)" >&2
  exit 2
fi
BLUE="${BLUE:-}"
if [[ -z "$BLUE" ]]; then
  if [[ -d /allah/blue/cloud/common/stacks ]]; then
    BLUE=/allah/blue
  elif [[ -d "$HERE/../stacks" ]]; then
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
  run apt install -y docker.io docker-compose-v2 git tmux htop curl wget iproute2 \
    sqlite3 openssl python3 cron
else
  run apt install -y docker.io docker-compose git tmux htop curl wget iproute2 \
    sqlite3 openssl python3 cron
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
HOSTNAME_VALUE=blue
if [[ "$HOST" == "ali-jp" ]]; then HOSTNAME_VALUE=ali-jp; fi
if [[ "$HOST" == "oracle-tokyo" ]]; then HOSTNAME_VALUE=oracle-tokyo; fi
if [[ "$HOST" == "oracle-tokyo2" ]]; then HOSTNAME_VALUE=oracle-tokyo-2; fi
if [[ "$HOST" == "oracle-a1" ]]; then HOSTNAME_VALUE=oracle-a1; fi
if [[ "$HOST" == "vultr-osk" ]]; then HOSTNAME_VALUE=vultr-osk; fi
print_step "Setting hostname to $HOSTNAME_VALUE..."
if [[ -f /etc/cloud/cloud.cfg ]]; then
  grep -q 'preserve_hostname' /etc/cloud/cloud.cfg 2>/dev/null || \
    echo 'preserve_hostname: true' | run tee -a /etc/cloud/cloud.cfg >/dev/null
fi
run hostnamectl set-hostname --static "$HOSTNAME_VALUE" 2>/dev/null \
  || run hostnamectl set-hostname "$HOSTNAME_VALUE"
print_success "Hostname: $(hostname)"

# --- timezone (cron reboot is wall-clock local; Ubuntu vixie ignores CRON_TZ) ---
print_header "TIMEZONE"
print_step "Asia/Singapore..."
run apt install -y tzdata
run timedatectl set-timezone Asia/Singapore \
  || run ln -sfn /usr/share/zoneinfo/Asia/Singapore /etc/localtime
print_success "Timezone: $(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone)"

# --- swap ---
print_header "SWAP"
if [[ "${SKIP_SWAP:-0}" == "1" ]]; then
  print_info "SKIP_SWAP=1"
elif [[ "$HOST" == "ali-jp" || "$HOST" == "oracle-tokyo" || "$HOST" == "oracle-tokyo2" ]]; then
  FORCE_SWAP=1
  print_info "$HOST: forcing ${SWAP_SIZE_GB}G swap (1 GiB RAM)"
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
elif [[ -d /allah/blue ]]; then
  # Tar/rsync tree without .git — overlay latest clone, keep local host runtime
  print_step "Overlaying latest blue onto existing /allah/blue..."
  git -C /allah clone https://github.com/rainfrog123/blue.git blue.new
  cp -a /allah/blue.new/. /allah/blue/
  rm -rf /allah/blue.new
else
  print_step "Cloning blue..."
  git -C /allah clone https://github.com/rainfrog123/blue.git
fi
BLUE=/allah/blue
print_success "Repository at $BLUE"

print_header "GIT /allah/freqtrade"
if [[ -d /allah/freqtrade/.git ]]; then
  print_step "Pulling existing /allah/freqtrade..."
  git -C /allah/freqtrade pull --ff-only || print_warn "git pull failed — continuing"
elif [[ -d /allah/freqtrade ]]; then
  print_warn "/allah/freqtrade exists without .git — keeping tree as-is"
else
  print_step "Cloning freqtrade..."
  git -C /allah clone https://github.com/rainfrog123/freqtrade.git
fi
print_success "Repository at /allah/freqtrade"

# --- BBR ---
print_header "TCP BBR & NETWORK"
print_step "Loading BBR..."
run modprobe tcp_bbr || true
print_step "Writing sysctl tuning..."
run tee /etc/sysctl.d/99-network-tuning.conf >/dev/null <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
# UDP/QUIC (Hy2) — 32 MiB caps; defaults raised for bursty flows
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
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

# --- daily reboot cron (fleet default) ---
print_header "CRONTAB"
if [[ "${SKIP_CRON:-0}" == "1" ]]; then
  print_info "SKIP_CRON=1"
else
  if ! command -v crontab >/dev/null 2>&1; then
    print_step "Installing cron (missing on Minimal images)..."
    run apt install -y cron
  fi
  print_step "Root crontab: daily reboot 07:00 Asia/Singapore..."
  CRON_TMP="$(mktemp)"
  {
    echo "CRON_TZ=Asia/Singapore"
    echo "# Daily host reboot at 07:00 Singapore time"
    echo "0 7 * * * /sbin/reboot"
    # Keep any other root jobs (drop prior reboot / CRON_TZ / our comment)
    run crontab -l 2>/dev/null \
      | grep -vE '^CRON_TZ=|/sbin/reboot|^# Daily host reboot' \
      || true
  } >"$CRON_TMP"
  run crontab "$CRON_TMP"
  rm -f "$CRON_TMP"
  print_success "crontab: 0 7 * * * /sbin/reboot (system TZ Asia/Singapore)"
fi

# --- bashrc ---
print_header "SHELL"
BASHRC=""
for _rc in "$BLUE/workstation/dotfiles/shell/bashrc" \
           "$BLUE/workstation/dotfiles/shell/Bashrc"; do
  [[ -f "$_rc" ]] && { BASHRC="$_rc"; break; }
done
if [[ -n "$BASHRC" ]]; then
  run rm -f /root/.bashrc
  run ln -sf "$BASHRC" /root/.bashrc
  print_success "bashrc linked"
else
  print_warn "bashrc not found — skip"
fi

# --- proxies (default = 3x-ui SQLite + cloudflared) ---
# LEGACY_PROXIES=1 → old hysteria/ss-rust/xray-* stacks (no MIGRATE marker)
print_header "PROXY STACKS (3x-ui default)"
if [[ "${SKIP_PROXIES:-0}" == "1" ]]; then
  print_info "SKIP_PROXIES=1"
else
  XUI_DIR="$BLUE/cloud/hosts/$HOST/3x-ui"
  run mkdir -p "$XUI_DIR/db" "$XUI_DIR/cert" "$XUI_DIR/acme" \
    "$BLUE/cloud/hosts/$HOST/hysteria/acme" \
    "$BLUE/cloud/hosts/$HOST/cloudflared"

  if [[ "${LEGACY_PROXIES:-0}" == "1" ]]; then
    print_warn "LEGACY_PROXIES=1 — skipping 3x-ui MIGRATE marker"
    run rm -f "$XUI_DIR/MIGRATE"
  else
    print_step "Seeding 3x-ui (SQLite) + MIGRATE for host=$HOST..."
    run touch "$XUI_DIR/MIGRATE"
    # Tracked inbound.env = Clash/proxy secrets (survives git clone).
    # Gitignored site.env = panel login (generated once).
    INBOUND_ENV="$XUI_DIR/inbound.env"
    if [[ -f "$INBOUND_ENV" ]]; then
      # shellcheck disable=SC1090
      set -a; source <(sed 's/\r$//' "$INBOUND_ENV"); set +a
      print_info "Loaded tracked inbound.env (SS/Hy2/Trojan secrets)"
    fi
    case "$HOST" in
      ali-jp) HY2_SNI="${HY2_SNI:-hyjp.hyas.site}" ;;
      azure) HY2_SNI="${HY2_SNI:-hyaz.hyas.site}" ;;
      oracle-tokyo) HY2_SNI="${HY2_SNI:-hyoci.hyas.site}" ;;
      oracle-tokyo2) HY2_SNI="${HY2_SNI:-hyoci2.hyas.site}" ;;
      oracle-a1) HY2_SNI="${HY2_SNI:-hyocia1.hyas.site}" ;;
      vultr-osk) HY2_SNI="${HY2_SNI:-hyvu.hyas.site}" ;;
      digi) HY2_SNI="${HY2_SNI:-hydo.hyas.site}" ;;
      ali) HY2_SNI="${HY2_SNI:-hyali.hyas.site}" ;;
      *) HY2_SNI="${HY2_SNI:-}" ;;
    esac
    if [[ ! -f "$XUI_DIR/site.env" ]]; then
      PANEL_PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 24)"
      PANEL_PATH="$(openssl rand -hex 6)"
      SS_PASS="${SS_PASS:-$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)}"
      HY2_PASS="${HY2_PASS:-$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 24)}"
      TROJAN_PASS="${TROJAN_PASS:-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)}"
      {
        printf 'PANEL_USER=admin\nPANEL_PASS=%s\nPANEL_BASE_PATH=/%s/\n' \
          "$PANEL_PASS" "$PANEL_PATH"
        printf 'SS_PASS=%s\nHY2_PASS=%s\nTROJAN_PASS=%s\n' \
          "$SS_PASS" "$HY2_PASS" "$TROJAN_PASS"
        [[ -n "$HY2_SNI" ]] && printf 'HY2_SNI=%s\n' "$HY2_SNI"
      } | run tee "$XUI_DIR/site.env" >/dev/null
      run chmod 600 "$XUI_DIR/site.env" || true
      print_success "Wrote $XUI_DIR/site.env (panel path=/$PANEL_PATH/)"
    else
      print_info "Keeping existing 3x-ui/site.env"
      # Merge tracked inbound secrets into site.env so seed uses Clash passwords
      if [[ -f "$INBOUND_ENV" ]]; then
        # shellcheck disable=SC1090
        set -a; source <(sed 's/\r$//' "$INBOUND_ENV"); set +a
        for k in SS_PASS HY2_PASS TROJAN_PASS HY2_SNI; do
          val="${!k:-}"
          [[ -n "$val" ]] || continue
          if grep -qE "^${k}=" "$XUI_DIR/site.env" 2>/dev/null; then
            run sed -i "s|^${k}=.*|${k}=${val}|" "$XUI_DIR/site.env"
          else
            printf '%s=%s\n' "$k" "$val" | run tee -a "$XUI_DIR/site.env" >/dev/null
          fi
        done
      fi
    fi
    # Ensure inbound.env exists for next clone (seed-inbounds will refresh it)
    if [[ ! -f "$INBOUND_ENV" && -n "${SS_PASS:-}" ]]; then
      {
        echo "# Tracked proxy secrets — keep in sync with network/clash/blue.yml"
        printf 'SS_PASS=%s\nHY2_PASS=%s\n' "$SS_PASS" "${HY2_PASS:-}"
        [[ -n "${HY2_SNI:-}" ]] && printf 'HY2_SNI=%s\n' "$HY2_SNI"
        printf 'TROJAN_PASS=%s\n' "${TROJAN_PASS:-}"
      } | run tee "$INBOUND_ENV" >/dev/null
      print_success "Wrote tracked $INBOUND_ENV"
    fi
    # Prefer existing Hy2 manual certs into 3x-ui/cert for panel Hy2 inbound
    if [[ -d "$BLUE/cloud/hosts/$HOST/hysteria/acme/manual" ]]; then
      run cp -a "$BLUE/cloud/hosts/$HOST/hysteria/acme/manual/." "$XUI_DIR/cert/" 2>/dev/null || true
    fi
  fi

  # Self-signed Hy2 certs (seed-inbounds.sh also ensures these; keep early for up.sh mounts)
  HY2_SNI_EARLY=""
  case "$HOST" in
    ali-jp) HY2_SNI_EARLY=hyjp.hyas.site ;;
    azure) HY2_SNI_EARLY=hyaz.hyas.site ;;
    oracle-tokyo) HY2_SNI_EARLY=hyoci.hyas.site ;;
    oracle-tokyo2) HY2_SNI_EARLY=hyoci2.hyas.site ;;
    oracle-a1) HY2_SNI_EARLY=hyocia1.hyas.site ;;
    vultr-osk) HY2_SNI_EARLY=hyvu.hyas.site ;;
    digi) HY2_SNI_EARLY=hydo.hyas.site ;;
    ali) HY2_SNI_EARLY=hyali.hyas.site ;;
  esac
  if [[ -n "$HY2_SNI_EARLY" && "${LEGACY_PROXIES:-0}" != "1" ]]; then
    print_step "Ensuring self-signed Hy2 cert for $HY2_SNI_EARLY..."
    MAN="$BLUE/cloud/hosts/$HOST/hysteria/acme/manual"
    run mkdir -p "$MAN" "$XUI_DIR/cert"
    if [[ ! -f "$MAN/${HY2_SNI_EARLY}.crt" ]]; then
      run openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$MAN/${HY2_SNI_EARLY}.key" \
        -out "$MAN/${HY2_SNI_EARLY}.crt" \
        -days 825 -subj "/CN=${HY2_SNI_EARLY}"
    fi
    run cp -a "$MAN/." "$XUI_DIR/cert/" 2>/dev/null || true
  fi

  if [[ ! -f "$BLUE/cloud/hosts/$HOST/cloudflared/site.env" \
     && ! -f "$BLUE/cloud/hosts/$HOST/cloudflared/.env" ]]; then
    print_info "No cloudflared site.env yet — tunnel may be skipped until token is added"
  fi

  # Beszel agent → fleet Hub (skip on Hub host or SKIP_BESZEL=1)
  # site.env is tracked in git (TOKEN/KEY). seed-host.sh still fills hosts/<host>/
  # from fleet stacks/beszel-agent/site.env when a new host dir lacks secrets.
  BZ_AGENT_DIR="$BLUE/cloud/hosts/$HOST/beszel-agent"
  BZ_STACK="$BLUE/cloud/common/stacks/beszel-agent"
  run mkdir -p "$BZ_AGENT_DIR"
  if [[ "${SKIP_BESZEL:-0}" == "1" ]]; then
    print_info "SKIP_BESZEL=1 — not seeding Beszel agent"
  elif [[ -f "$BLUE/cloud/hosts/$HOST/beszel/HUB" || -f "$BLUE/cloud/hosts/$HOST/beszel/hub" ]]; then
    print_info "beszel/HUB present — this host runs the Hub; agent stack skipped"
  else
    print_step "Seeding Beszel agent for host=$HOST..."
    if [[ -x "$BZ_STACK/seed-host.sh" || -f "$BZ_STACK/seed-host.sh" ]]; then
      if bash "$BZ_STACK/seed-host.sh" "$HOST"; then
        print_success "Beszel agent site.env ready"
      else
        print_warn "Beszel seed failed — overlay stacks/beszel-agent/site.env then: bash $BZ_STACK/seed-host.sh $HOST"
      fi
    else
      print_warn "missing $BZ_STACK/seed-host.sh"
    fi
  fi

  print_step "up-all.sh $HOST..."
  bash "$BLUE/cloud/common/stacks/up-all.sh" "$HOST" \
    || print_warn "up-all reported issues — check hosts/$HOST/ site files"

  if [[ -f "$XUI_DIR/MIGRATE" && -f "$XUI_DIR/site.env" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$XUI_DIR/site.env"; set +a
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 3x-ui; then
      print_step "Applying panel login from site.env..."
      docker exec 3x-ui /app/x-ui setting \
        -username "${PANEL_USER:-admin}" \
        -password "${PANEL_PASS}" \
        -webBasePath "${PANEL_BASE_PATH:-/}" \
        >/dev/null 2>&1 || print_warn "panel setting apply failed (set later via UI/SSH)"
      docker restart 3x-ui >/dev/null 2>&1 || true
      sleep 2
      print_success "Panel: ssh -L 2053:127.0.0.1:2053 $HOST → http://127.0.0.1:2053${PANEL_BASE_PATH:-/}"

      if [[ "${SKIP_XUI_SEED:-0}" == "1" ]]; then
        print_info "SKIP_XUI_SEED=1 — not seeding SS/Hy2/Trojan inbounds"
      else
        print_step "Seeding default inbounds (SS / Hy2 / Trojan)..."
        if bash "$BLUE/cloud/common/stacks/3x-ui/seed-inbounds.sh" "$HOST"; then
          print_success "3x-ui ready to use (SS/Hy2/Trojan + Xray clients) — inbound.env + site.env"
        else
          print_warn "inbound seed failed — run: bash cloud/common/stacks/3x-ui/seed-inbounds.sh $HOST"
        fi
      fi
    fi
  fi
  print_success "Proxy bring-up attempted (default=3x-ui)"
fi

# --- cleanup ---
print_header "CLEANUP"
run apt autoremove -y || true
run apt clean || true

print_header "SETUP COMPLETE"
print_success "host=$HOST"
print_info "  • Hostname: $(hostname)"
print_info "  • Proxies: 3x-ui (SQLite) + cloudflared by default (MIGRATE)"
print_info "  • 3x-ui: panel login + SS/Hy2/Trojan seeded (SKIP_XUI_SEED=1 to skip)"
if [[ -f "$BLUE/cloud/hosts/$HOST/3x-ui/site.env" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$BLUE/cloud/hosts/$HOST/3x-ui/site.env"; set +a
  print_info "  • Panel: ssh -L 2053:127.0.0.1:2053 $HOST → http://127.0.0.1:2053${PANEL_BASE_PATH:-/}"
  print_info "  • Panel user=${PANEL_USER:-admin} pass=${PANEL_PASS:-?}"
  [[ -n "${SS_PASS:-}" ]] && print_info "  • SS :12033 pass=$SS_PASS"
  [[ -n "${HY2_PASS:-}" && -n "${HY2_SNI:-}" ]] && print_info "  • Hy2 :443/udp pass=$HY2_PASS sni=$HY2_SNI"
  print_info "  • Clash snippet: hosts/$HOST/3x-ui/clash.snippet.yml"
fi
print_info "  • Monitor: Beszel agent → https://beszel.hyas.site (SKIP_BESZEL=1 to skip)"
print_info "  • Legacy stacks: LEGACY_PROXIES=1"
print_info "  • Site: hosts/$HOST/  · Repo: $BLUE"
print_info "  • BBR + fq: enabled"
print_info "  • Cron: daily reboot 07:00 Asia/Singapore (SKIP_CRON=1 to skip)"
[[ -n "${INIT_LOG:-}" ]] && print_info "  • Init log: $INIT_LOG  (tail -f $INIT_LOG)"

if [[ "${SKIP_REBOOT:-0}" == "1" ]]; then
  print_info "SKIP_REBOOT=1 — not rebooting"
else
  echo -e "${YELLOW}Rebooting in 5 seconds...${NC}"
  sleep 5
  run reboot
fi
