#!/bin/bash

# Restart Appointment Monitor Script
# Stops the current monitor, then starts a fresh one

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
SESSION_NAME="appointment_monitor"
PYTHON_PATH="/allah/freqtrade/.venv/bin/python3"

echo "🔄 Restarting appointment monitor..."

# Check if monitor is currently running
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    echo "📊 Current monitor session detected - stopping..."
    tmux kill-session -t "$SESSION_NAME"
    sleep 2
else
    echo "ℹ️ No active monitor session found"
fi

# Kill any remaining monitoring processes
monitor_pids=$(pgrep -f "monitor_appointments.py" 2>/dev/null)
if [ -n "$monitor_pids" ]; then
    echo "🧹 Cleaning up remaining monitor processes..."
    echo "$monitor_pids" | xargs kill 2>/dev/null
    sleep 2
fi

# Start fresh monitor session
echo "🚀 Starting fresh monitor session..."
cd "$SCRIPT_DIR"
tmux new-session -d -s "$SESSION_NAME" -c "$SCRIPT_DIR"
tmux send-keys -t "$SESSION_NAME" "cd '$SCRIPT_DIR'" Enter
tmux send-keys -t "$SESSION_NAME" "$PYTHON_PATH monitor_appointments.py" Enter

# Verify startup
sleep 2
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    echo "✅ Monitor restarted successfully!"
    echo ""
    echo "📋 Useful commands:"
    echo "   tmux attach -t $SESSION_NAME       # View monitor session"
    echo "   tmux kill-session -t $SESSION_NAME # Stop monitor"
    echo "   tmux ls                            # List all sessions"
    echo ""
    echo "🛑 To stop the monitor:"
    echo "   1. Attach to session: tmux attach -t $SESSION_NAME"
    echo "   2. Press Ctrl+C to stop the Python script"
    echo "   3. Press Ctrl+B then D to detach (or just close terminal)"
    echo "   OR directly: tmux kill-session -t $SESSION_NAME"
else
    echo "❌ Restart failed - monitor session not found"
    echo "💡 Check if Python script has errors by running manually:"
    echo "   $PYTHON_PATH monitor_appointments.py"
fi