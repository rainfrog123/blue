#!/bin/bash

# Restart Stomatology Monitor Script with Safety Support
# Stops the current monitor and safety systems, then starts fresh ones

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
SESSION_NAME="stomatology_monitor"
SAFETY_PID_FILE="$SCRIPT_DIR/.stomatology_safety.pid"

echo "🔄 Restarting Stomatology Monitor with safety systems..."

# Check if monitor is currently running
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    echo "📊 Current monitor session detected"
elif [ -f "$SAFETY_PID_FILE" ]; then
    echo "🛡️ Safety monitor detected"
else
    echo "ℹ️ No active monitor found"
fi

# Stop the monitor and clear logs  
echo "🛑 Stopping current systems..."
"$SCRIPT_DIR/stop.sh"

# Wait for proper cleanup (safety monitor + tmux session)
echo "⏳ Waiting for complete shutdown..."
sleep 3

# Verify everything is stopped
MAX_WAIT=10
wait_count=0
while [ $wait_count -lt $MAX_WAIT ]; do
    # Check if tmux session is gone
    if ! tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        # Check if safety monitor PID file is gone
        if [ ! -f "$SAFETY_PID_FILE" ]; then
            # Check if any monitor processes are still running
            if ! pgrep -f "stomatology_monitor.py" >/dev/null 2>&1; then
                echo "✅ Clean shutdown confirmed"
                break
            fi
        fi
    fi
    
    echo "⏳ Still waiting for cleanup... ($((wait_count + 1))/$MAX_WAIT)"
    sleep 1
    wait_count=$((wait_count + 1))
done

# Warn if cleanup took too long
if [ $wait_count -eq $MAX_WAIT ]; then
    echo "⚠️ Warning: Cleanup took longer than expected, but proceeding with restart"
fi

# Start the monitor with new safety systems
echo "🚀 Starting fresh monitor..."
"$SCRIPT_DIR/start.sh"

# Brief verification that startup was successful
sleep 2
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    if [ -f "$SAFETY_PID_FILE" ]; then
        echo "🎉 Restart completed successfully!"
        echo "✅ Monitor session: Active"
        echo "🛡️ Safety monitor: Active" 
    else
        echo "⚠️ Monitor started but safety monitor may not be active"
    fi
else
    echo "❌ Restart failed - monitor session not found"
    echo "💡 Try running './start.sh' manually to see error details"
fi 