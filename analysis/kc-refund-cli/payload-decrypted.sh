#!/usr/bin/env bash
# KC 一键退款 · 命令行交互载荷（bash）· hacker theme
# 仅交互 + 调后端接口；退款业务逻辑全部在服务端，脚本零感知。服务端加密下发本文件。
B="${KC_BASE:-https://kc.szbjxbj.com}"
TTY=/dev/tty
[ -r "$TTY" ] || TTY=/dev/stdin
e(){ printf '\033[%sm' "$1"; }
N=$(e '38;5;46'); DG=$(e '38;5;28'); CY=$(e '38;5;51'); RD=$(e '38;5;196'); AM=$(e '38;5;214'); MG=$(e '38;5;201'); D=$(e '2'); H=$(e '1'); Z=$(e '0')
RULE='══════════════════════════════════════════'
# OSC 8 终端超链接：显示文字、隐藏真实 URL，可点击跳转
link(){ printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$1" "$2"; }
# URL 解码（用户可能粘贴 %3A%3A 等编码形式的 sessionToken）
urldecode(){ local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }

# 文字 LOGO（figlet 风格）
FR1=' _  __  ____   ____   _____  _____  _   _  _   _  ____  '
FR2='| |/ / / ___|  |  _ \ | ____||  ___|| | | || \ | ||  _ \ '
FR3="| ' / | |      | |_) ||  _|  | |_   | | | ||  \| || | | |"
FR4='| . \ | |___   |  _ < | |___ |  _|  | |_| || |\  || |_| |'
FR5='|_|\_\ \____|  |_| \_\|_____||_|     \___/ |_| \_||____/ '
printf '\n'
printf '  %s%s%s\n' "$N" "$FR1" "$Z"
printf '  %s%s%s\n' "$N" "$FR2" "$Z"
printf '  %s%s%s\n' "$N" "$FR3" "$Z"
printf '  %s%s%s\n' "$N" "$FR4" "$Z"
printf '  %s%s%s\n' "$N" "$FR5" "$Z"
printf '  %s%s%s\n' "$DG" "$RULE" "$Z"
STATS=$(curl -fsSL --noproxy '*' --connect-timeout 10 --max-time 20 "$B/pub/refund-cli/stats?fmt=text" 2>/dev/null || true)
CNT=$(printf '%s\n' "$STATS" | sed -n 's/^COUNT=//p'); [ -z "$CNT" ] && CNT=0
TOT=$(printf '%s\n' "$STATS" | sed -n 's/^TOTAL_USD=//p'); [ -z "$TOT" ] && TOT=0.00
SP=$(printf '%s\n' "$STATS" | sed -n 's/^SPONSOR=//p')
ANN=$(printf '%s\n' "$STATS" | sed -n 's/^ANN=//p')
printf '  %s[∷]%s 累计退款  %s$%s%s\n' "$N" "$Z" "$H$N" "$TOT" "$Z"
printf '  %s[∷]%s 累计笔数  %s%s%s\n' "$N" "$Z" "$H$N" "$CNT" "$Z"
printf '  %s%s%s\n' "$DG" "$RULE" "$Z"
printf '  %s[i] 退款秒到账 · 实时结算%s\n' "$H$N" "$Z"
printf '   %s1.%s %s退得越早，可退金额越高（按订阅剩余时长比例结算）%s\n' "$N" "$Z" "$D" "$Z"
printf '   %s2.%s %s退款后订阅立即转 Free，Token 随之失效%s\n' "$N" "$Z" "$D" "$Z"
printf '   %s3.%s %s超额也可以退，不影响退款金额%s\n' "$N" "$Z" "$D" "$Z"
printf '   %s4.%s %s换号更稳：建议闲鱼买全新 Free 账号重开订阅，别复用退过的号%s\n' "$N" "$Z" "$D" "$Z"
printf '   %s5.%s %s新手先正常开通 Pro 订阅体验，熟悉后再按需退款%s\n' "$N" "$Z" "$D" "$Z"
printf '   %s6.%s %s本工具纯公益免费，服务器成本全靠作者自掏腰包，若帮到你欢迎自愿赞助一下%s\n' "$N" "$Z" "$H$RD" "$Z"
if [ -n "$ANN" ]; then
  printf '\n'
  printf '   %s公告：%s%s\n' "$AM" "$ANN" "$Z"
fi
printf '\n'

valid_token(){
  case "$1" in user_*::*) return 0 ;; esac
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$'
}

TOK=""
while true; do
  printf '  %s[»] 请输入 Cursor Token（全格式支持）❯%s ' "$N" "$Z"
  IFS= read -r TOK < "$TTY" || exit 0
  TOK=$(printf '%s' "$TOK" | tr -d '[:space:]')
  case "$TOK" in *%*) TOK=$(urldecode "$TOK") ;; esac
  case "$TOK" in q|Q) printf '\n'; exit 0 ;; esac
  if [ -z "$TOK" ]; then printf '  %s[!] 输入为空，请重试%s\n\n' "$AM" "$Z"; continue; fi
  if valid_token "$TOK"; then break; fi
  printf '  %s[✗] 格式错误，请重新粘贴完整 token%s\n\n' "$RD" "$Z"
done

# 后台发起请求
BODY=$(printf '{"token":"%s"}' "$TOK")
RF=$(mktemp)
( curl -sS --noproxy '*' --connect-timeout 20 --max-time 120 -H 'Content-Type: application/json' -X POST -d "$BODY" "$B/pub/refund-cli/refund?fmt=text" -o "$RF" 2>/dev/null ) &
PID=$!
# 加载动画：转圈（braille spinner）
FR=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
i=0
printf '\n'
while kill -0 "$PID" 2>/dev/null; do
  printf '\r  %s%s%s %s正在处理退款…%s' "$N" "${FR[$((i % ${#FR[@]}))]}" "$Z" "$D" "$Z"
  i=$((i + 1)); sleep 0.1
done
wait "$PID" 2>/dev/null
printf '\r\033[K'
RESP=$(cat "$RF" 2>/dev/null); rm -f "$RF"

ST=$(printf '%s\n' "$RESP" | sed -n 's/^__KCR_STATUS__=//p')
AMT=$(printf '%s\n' "$RESP" | sed -n 's/^__KCR_AMOUNT__=//p')
MSG=$(printf '%s\n' "$RESP" | sed -n 's/^__KCR_MSG__=//p')
RSP=$(printf '%s\n' "$RESP" | sed -n 's/^__KCR_SPONSOR__=//p'); [ -z "$RSP" ] && RSP="$SP"
[ -z "$RESP" ] && { ST="failed"; MSG="请求失败或超时，请稍后重试"; }

case "$ST" in
  success)      printf '  %s[✓] 退款成功  %s$%s%s\n' "$N" "$H$N" "$AMT" "$Z" ;;
  pending)      printf '  %s[✓] 已提交  %s$%s%s  %s░ 同步中%s\n' "$N" "$H$N" "$AMT" "$Z" "$D" "$Z" ;;
  already_free) printf '  %s[·] %s%s\n' "$AM" "$MSG" "$Z" ;;
  ratelimited)  printf '  %s[!] %s%s\n' "$AM" "$MSG" "$Z" ;;
  *)            printf '  %s[✗] %s%s\n' "$RD" "$MSG" "$Z" ;;
esac

if [ -n "$RSP" ]; then
  printf '  %s[♥] 支持作者 · %s' "$MG" "$CY"
  link "$RSP" "按住 Ctrl 单击此处赞助"
  printf '%s\n' "$Z"
fi
printf '  %s[群] 交流 Q 群 · %s144247531%s\n' "$MG" "$CY" "$Z"
printf '\n'
