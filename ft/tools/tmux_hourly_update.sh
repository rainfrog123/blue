#!/bin/bash
#
# Run daily_update.sh every hour in a tmux session
#

SESSION_NAME="hourly_update"
SCRIPT_PATH="/allah/blue/ft/tools/daily_update.sh"

# Kill existing session if it exists
tmux kill-session -t "$SESSION_NAME" 2>/dev/null

# Create new detached tmux session running the hourly loop
tmux new-session -d -s "$SESSION_NAME" bash -c "
while true; do
    echo '=========================================='
    echo 'Starting update at: \$(date)'
    echo '=========================================='
    
    bash $SCRIPT_PATH
    
    echo ''
    echo 'Update complete. Sleeping for 1 hour...'
    echo 'Next run at: \$(date -d '+1 hour')'
    echo ''
    
    sleep 3600
done
"

echo "Started tmux session: $SESSION_NAME"
echo "To attach: tmux attach -t $SESSION_NAME"
echo "To view:   tmux ls"
echo "To kill:   tmux kill-session -t $SESSION_NAME"
