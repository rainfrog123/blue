#!/bin/bash
#
# IPv6 control for this VPS.
#
# Prefer "outbound off" when you still need inbound IPv6 (Hysteria, SSH -6, …)
# but do not want the box to *initiate* IPv6 egress (billing / policy).
#
# Usage:
#   sudo ./ipv6.sh status
#   sudo ./ipv6.sh outbound off|on|status
#   sudo ./ipv6.sh full off|on|status     # hard disable whole stack (last resort)
#
set -euo pipefail

GAI_MARK_BEGIN="# BEGIN blue-ipv6-prefer4"
GAI_MARK_END="# END blue-ipv6-prefer4"
GAI_FILE="/etc/gai.conf"
NFT_TABLE="blue_ipv6"
UNIT_PATH="/etc/systemd/system/blue-ipv6-outbound.service"
FULL_SYSCTL="/etc/sysctl.d/99-disable-ipv6.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_info()    { echo -e "${CYAN}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
print_error()   { echo -e "${RED}✗${NC} $1" >&2; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    print_error "Run as root: sudo $0 $*"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Prefer IPv4 for dual-stack apps (soft; AAAA-only hosts still use IPv6)
# ---------------------------------------------------------------------------
gai_prefer4_on() {
  need_root
  gai_prefer4_off
  {
    echo ""
    echo "$GAI_MARK_BEGIN"
    echo "# Prefer IPv4 over IPv6 when both A and AAAA exist (RFC 3484)"
    echo "precedence  ::ffff:0:0/96  100"
    echo "$GAI_MARK_END"
  } >> "$GAI_FILE"
}

gai_prefer4_off() {
  need_root
  if [[ -f "$GAI_FILE" ]] && grep -q "$GAI_MARK_BEGIN" "$GAI_FILE"; then
    sed -i "/$GAI_MARK_BEGIN/,/$GAI_MARK_END/d" "$GAI_FILE"
  fi
}

gai_prefer4_active() {
  [[ -f "$GAI_FILE" ]] && grep -q "$GAI_MARK_BEGIN" "$GAI_FILE"
}

# ---------------------------------------------------------------------------
# Hard block: NEW outbound IPv6; allow replies so inbound services keep working
# ---------------------------------------------------------------------------
nft_apply() {
  need_root
  # Idempotent: drop then recreate (nft -f merges into an existing table)
  nft delete table ip6 "$NFT_TABLE" 2>/dev/null || true
  nft -f - <<EOF
table ip6 ${NFT_TABLE} {
  chain outbound {
    type filter hook output priority filter; policy accept;

    oif "lo" accept
    ct state established,related accept
    ip6 daddr fe80::/10 accept
    ip6 daddr ff00::/8 accept

    # Block newly initiated outbound IPv6 (replies to inbound still pass above)
    ct state new reject with icmpv6 type admin-prohibited
  }
}
EOF
}

nft_clear() {
  need_root
  nft delete table ip6 "$NFT_TABLE" 2>/dev/null || true
}

nft_active() {
  nft list table ip6 "$NFT_TABLE" &>/dev/null
}

unit_install() {
  need_root
  local self
  self="$(readlink -f "$0")"
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Block newly initiated outbound IPv6 (blue)
After=network-pre.target nftables.service
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${self} outbound apply
ExecStop=${self} outbound clear-rules

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now blue-ipv6-outbound.service >/dev/null
}

unit_remove() {
  need_root
  if [[ -f "$UNIT_PATH" ]]; then
    systemctl disable --now blue-ipv6-outbound.service >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
  fi
}

show_addrs() {
  echo ""
  print_info "Global IPv6 addresses:"
  if ip -6 -o addr show scope global 2>/dev/null | grep -q .; then
    ip -6 -o addr show scope global | sed 's/^/    /'
  else
    echo "    (none)"
  fi
  echo ""
  print_info "IPv6 default route:"
  if ip -6 route show default 2>/dev/null | grep -q .; then
    ip -6 route show default | sed 's/^/    /'
  else
    echo "    (none)"
  fi
}

cmd_outbound_status() {
  if nft_active; then
    print_info "Outbound IPv6 NEW: ${RED}BLOCKED${NC} (nft table ip6 ${NFT_TABLE})"
  else
    print_info "Outbound IPv6 NEW: ${GREEN}ALLOWED${NC}"
  fi
  if gai_prefer4_active; then
    print_info "gai.conf: prefer IPv4 for dual-stack lookups"
  else
    print_info "gai.conf: default precedence"
  fi
  if systemctl is-enabled blue-ipv6-outbound.service &>/dev/null; then
    print_info "persist: blue-ipv6-outbound.service enabled"
  else
    print_info "persist: (service not installed)"
  fi
  show_addrs
}

cmd_outbound_off() {
  need_root
  if [[ -f "$FULL_SYSCTL" ]] || [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" == "1" ]]; then
    print_warn "Full IPv6 disable is active — turn that off first: sudo $0 full on"
  fi
  gai_prefer4_on
  nft_apply
  unit_install
  print_success "Outbound IPv6 blocked (inbound replies still work)"
  print_info "Dual-stack apps prefer IPv4 via ${GAI_FILE}"
  print_info "Persistent via blue-ipv6-outbound.service"
  show_addrs
}

cmd_outbound_on() {
  need_root
  unit_remove
  nft_clear
  gai_prefer4_off
  print_success "Outbound IPv6 allowed again"
  show_addrs
}

# Internal hooks for the systemd unit (no unit churn)
cmd_outbound_apply() {
  need_root
  gai_prefer4_on
  nft_apply
}

cmd_outbound_clear_rules() {
  need_root
  nft_clear
}

# ---------------------------------------------------------------------------
# Full stack disable (last resort — breaks inbound IPv6 too)
# ---------------------------------------------------------------------------
full_disabled() {
  [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)" == "1" ]]
}

apply_disable_ipv6() {
  local value="$1"
  sysctl -w "net.ipv6.conf.all.disable_ipv6=${value}" >/dev/null
  sysctl -w "net.ipv6.conf.default.disable_ipv6=${value}" >/dev/null
  for iface in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -e "$iface" ]] || continue
    echo "$value" > "$iface" 2>/dev/null || true
  done
}

cmd_full_status() {
  if full_disabled; then
    print_info "IPv6 stack: ${RED}OFF${NC} (disable_ipv6=1)"
  else
    print_info "IPv6 stack: ${GREEN}ON${NC}"
  fi
  if [[ -f "$FULL_SYSCTL" ]]; then
    print_info "persist: $FULL_SYSCTL"
  else
    print_info "persist: (no $FULL_SYSCTL)"
  fi
  show_addrs
}

cmd_full_off() {
  need_root
  print_warn "Full disable kills inbound IPv6 too. Prefer: sudo $0 outbound off"
  # Clear outbound mode first so we do not leave stale nft/gai behind
  unit_remove
  nft_clear
  gai_prefer4_off
  cat > "$FULL_SYSCTL" <<EOF
# Managed by infra/cloud/common/lib/ipv6.sh — disable IPv6 entirely
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  apply_disable_ipv6 1
  print_success "IPv6 fully disabled"
  show_addrs
}

cmd_full_on() {
  need_root
  rm -f "$FULL_SYSCTL"
  apply_disable_ipv6 0
  print_success "IPv6 stack enabled"
  print_info "Address may take a few seconds (SLAAC/DHCPv6)"
  show_addrs
}

cmd_status() {
  echo ""
  print_info "=== outbound (recommended) ==="
  cmd_outbound_status
  echo ""
  print_info "=== full stack ==="
  cmd_full_status
}

usage() {
  cat <<EOF
Usage: sudo $0 <command>

  status                 Show outbound + full-stack state

  outbound off           Block NEW outbound IPv6; keep inbound working
  outbound on            Allow outbound IPv6 again
  outbound status        Outbound mode only

  full off               Disable entire IPv6 stack (breaks inbound too)
  full on                Re-enable IPv6 stack
  full status            Full-stack mode only

Recommended for this VPS (IPv6 services + stop egress):
  sudo $0 outbound off
EOF
}

main() {
  case "${1:-status}" in
    status|st)              cmd_status ;;
    -h|--help|help)         usage ;;

    outbound)
      case "${2:-status}" in
        off|disable|block)  cmd_outbound_off ;;
        on|enable|allow)    cmd_outbound_on ;;
        status|st)          cmd_outbound_status ;;
        apply)              cmd_outbound_apply ;;
        clear-rules)        cmd_outbound_clear_rules ;;
        *) print_error "Unknown: outbound $2"; usage; exit 1 ;;
      esac
      ;;

    full)
      case "${2:-status}" in
        off|disable)        cmd_full_off ;;
        on|enable)          cmd_full_on ;;
        status|st)          cmd_full_status ;;
        *) print_error "Unknown: full $2"; usage; exit 1 ;;
      esac
      ;;

    # Back-compat aliases from the first version
    off|disable)            cmd_full_off ;;
    on|enable)              cmd_full_on ;;
    toggle|t)
      need_root
      if full_disabled; then cmd_full_on; else cmd_full_off; fi
      ;;

    *)
      print_error "Unknown command: $1"
      usage
      exit 1
      ;;
  esac
}

main "$@"
