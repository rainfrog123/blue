#!/bin/bash
cd /allah/freqtrade

# Save the current branch
current_branch=$(git branch --show-current)

# Get all local branches and run setup for each
for branch in $(git branch | sed 's/^[* ]*//'); do
    echo "Processing branch: $branch"
    git checkout "$branch"
    # Pipe "Y" to make setup.sh non-interactive (install dev dependencies which includes everything)
    echo "Y" | ./setup.sh -u
done

# Return to the original branch
git checkout "$current_branch"
pip install fastparquet matplotlib
cd /allah/blue/freq/project/tools

/allah/freqtrade/.venv/bin/python3 daily_trades.py
/allah/freqtrade/.venv/bin/python3 convert_to_feather.py
freqtrade download-data --userdir /allah/blue/freq/project/user_data --config /allah/blue/freq/project/user_data/config/main.json --timerange 20250801- --timeframes 1m 3m 5m 15m 30m 1h 4h --datadir /allah/freqtrade/user_data/data/binance
