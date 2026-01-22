#!/bin/bash

# Stomatology Appointment Monitor Startup Script with Safety Protection
# This script starts the stomatology monitor in a tmux session with built-in safety limits

SESSION_NAME="stomatology_monitor"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PYTHON_PATH="/allah/freqtrade/.venv/bin/python3"
MAIN_SCRIPT="$SCRIPT_DIR/stomatology_monitor.py"

# 🛡️ SAFETY CONFIGURATION
MAX_CPU_PERCENT=30
MAX_MEMORY_MB=200
MAX_LOG_SIZE_MB=50
SAFETY_CHECK_INTERVAL=60
SAFETY_PID_FILE="$SCRIPT_DIR/.stomatology_safety.pid"

echo "🦷 Starting Stomatology Monitor with safety protection..."

# Function to check if process is running
check_process() {
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Function to get resource usage
get_resource_usage() {
    local pid=$(tmux list-panes -t "$SESSION_NAME" -F "#{pane_pid}" 2>/dev/null)
    if [ -n "$pid" ]; then
        # Get child Python process
        local python_pid=$(pgrep -P "$pid" python3 2>/dev/null | head -1)
        if [ -n "$python_pid" ]; then
            local cpu=$(ps -p "$python_pid" -o %cpu= 2>/dev/null | tr -d ' ')
            local mem=$(ps -p "$python_pid" -o rss= 2>/dev/null | tr -d ' ')
            local mem_mb=$((mem / 1024))
            echo "$cpu,$mem_mb"
            return 0
        fi
    fi
    echo "0,0"
    return 1
}

# Function to check log file sizes
check_log_sizes() {
    local reg_size=0
    local success_size=0
    
    if [ -f "$SCRIPT_DIR/stomatology_reg.log" ]; then
        reg_size=$(stat -c%s "$SCRIPT_DIR/stomatology_reg.log" 2>/dev/null || echo 0)
    fi
    
    if [ -f "$SCRIPT_DIR/stomatology_success.log" ]; then
        success_size=$(stat -c%s "$SCRIPT_DIR/stomatology_success.log" 2>/dev/null || echo 0)
    fi
    
    # Convert to MB
    local reg_mb=$((reg_size / 1024 / 1024))
    local success_mb=$((success_size / 1024 / 1024))
    
    echo "$reg_mb,$success_mb"
}

# Function to format runtime
format_runtime() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    printf "%02d:%02d:%02d" $hours $minutes $secs
}

# Safety monitor background process
safety_monitor() {
    local start_time=$(date +%s)
    
    while true; do
        if ! check_process; then
            echo "🛡️ Safety monitor: Main process not found, exiting safety monitor"
            break
        fi
        
        local current_time=$(date +%s)
        local runtime=$((current_time - start_time))
        
        # Check resource usage
        local usage=$(get_resource_usage)
        local cpu=$(echo "$usage" | cut -d',' -f1)
        local mem=$(echo "$usage" | cut -d',' -f2)
        
        if [ -n "$cpu" ] && [ -n "$mem" ]; then
            # Check CPU limit
            if (( $(echo "$cpu > $MAX_CPU_PERCENT" | bc -l) )); then
                echo "🛡️ Safety monitor: CPU usage too high (${cpu}% > ${MAX_CPU_PERCENT}%), stopping monitor"
                tmux kill-session -t "$SESSION_NAME" 2>/dev/null
                break
            fi
            
            # Check memory limit
            if [ "$mem" -gt "$MAX_MEMORY_MB" ]; then
                echo "🛡️ Safety monitor: Memory usage too high (${mem}MB > ${MAX_MEMORY_MB}MB), stopping monitor"
                tmux kill-session -t "$SESSION_NAME" 2>/dev/null
                break
            fi
        fi
        
        # Check log file sizes
        local log_sizes=$(check_log_sizes)
        local reg_mb=$(echo "$log_sizes" | cut -d',' -f1)
        local success_mb=$(echo "$log_sizes" | cut -d',' -f2)
        
        if [ "$reg_mb" -gt "$MAX_LOG_SIZE_MB" ] || [ "$success_mb" -gt "$MAX_LOG_SIZE_MB" ]; then
            echo "🛡️ Safety monitor: Log files too large (${reg_mb}MB, ${success_mb}MB > ${MAX_LOG_SIZE_MB}MB), stopping monitor"
            tmux kill-session -t "$SESSION_NAME" 2>/dev/null
            break
        fi
        
        # Status update
        local runtime_formatted=$(format_runtime $runtime)
        echo "🛡️ Safety monitor: Runtime: ${runtime_formatted}, CPU: ${cpu}%, Memory: ${mem}MB, Logs: ${reg_mb}MB/${success_mb}MB"
        
        sleep $SAFETY_CHECK_INTERVAL
    done
    
    # Clean up PID file
    rm -f "$SAFETY_PID_FILE"
}

# Check if already running
if check_process; then
    echo "⚠️  Monitor session '$SESSION_NAME' already exists!"
    echo "🔍 Current session info:"
    tmux list-sessions | grep "$SESSION_NAME" || echo "Session not found in list"
    echo "💡 Use './stop.sh' to stop the current session or './restart.sh' to restart"
    exit 1
fi

# Check if Python script exists
if [ ! -f "$MAIN_SCRIPT" ]; then
    echo "❌ Python script not found: $MAIN_SCRIPT"
    exit 1
fi

# Check if Python path is valid
if [ ! -x "$PYTHON_PATH" ]; then
    echo "❌ Python executable not found: $PYTHON_PATH"
    exit 1
fi

# Create new tmux session
echo "🚀 Creating new tmux session: $SESSION_NAME"
tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR"

# Run the monitor script
echo "🔍 Starting stomatology monitor..."
tmux send-keys -t "$SESSION_NAME" "cd '$SCRIPT_DIR' && '$PYTHON_PATH' '$MAIN_SCRIPT'" Enter

# Wait a moment for startup
sleep 2

# Check if session started successfully
if ! check_process; then
    echo "❌ Failed to start monitor session"
    exit 1
fi

# Start safety monitor in background
echo "🛡️ Starting safety monitor..."
safety_monitor &
echo $! > "$SAFETY_PID_FILE"

# Show session info
echo "✅ Monitor started successfully!"
echo "📋 Session: $SESSION_NAME"
echo "🖥️  View session: tmux attach-session -t $SESSION_NAME"
echo "⏹️  Stop session: ./stop.sh"
echo "🔄 Restart session: ./restart.sh"
echo "🛡️ Safety limits:"
echo "   - Max CPU: ${MAX_CPU_PERCENT}%"
echo "   - Max memory: ${MAX_MEMORY_MB}MB"
echo "   - Max log size: ${MAX_LOG_SIZE_MB}MB"
echo "   - Safety check interval: ${SAFETY_CHECK_INTERVAL}s"

# Show initial resource usage
sleep 1
usage=$(get_resource_usage)
cpu=$(echo "$usage" | cut -d',' -f1)
mem=$(echo "$usage" | cut -d',' -f2)
echo "📊 Initial resource usage: CPU: ${cpu}%, Memory: ${mem}MB"

echo "🎉 Stomatology monitor is now running!"
echo "💡 Check logs: tail -f stomatology_success.log stomatology_reg.log" 