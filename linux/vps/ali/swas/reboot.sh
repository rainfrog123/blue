#!/bin/bash
# SWAS Auto-Reboot Script
# Runs in tmux, reboots instance daily at 12:00 PM CST (noon, UTC+8)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/cli.py"

start_instance() {
    echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S CST')] Checking instance status..."
    status=$(python3 "$CLI" info 2>&1 | grep "Status:" | awk '{print $2}')
    
    if [ "$status" = "Running" ]; then
        echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S CST')] Instance running, rebooting..."
        python3 "$CLI" reboot
    else
        echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S CST')] Instance stopped, starting..."
        python3 "$CLI" start
    fi
    echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S CST')] Done."
}

# Calculate seconds until next 12:00 PM CST (noon)
seconds_until_noon() {
    local now=$(TZ=Asia/Shanghai date +%s)
    local today_noon=$(TZ=Asia/Shanghai date -d "today 12:00" +%s)
    local tomorrow_noon=$(TZ=Asia/Shanghai date -d "tomorrow 12:00" +%s)
    
    if [ $now -lt $today_noon ]; then
        echo $((today_noon - now))
    else
        echo $((tomorrow_noon - now))
    fi
}

# Main loop
echo "=========================================="
echo "SWAS Auto-Reboot Service"
echo "Schedule: Daily at 12:00 PM CST (noon)"
echo "=========================================="

while true; do
    wait_seconds=$(seconds_until_noon)
    next_run=$(TZ=Asia/Shanghai date -d "+${wait_seconds} seconds" '+%Y-%m-%d %H:%M:%S CST')
    echo "[$(TZ=Asia/Shanghai date '+%Y-%m-%d %H:%M:%S CST')] Next reboot: $next_run (in ${wait_seconds}s)"
    
    sleep $wait_seconds
    start_instance
done
