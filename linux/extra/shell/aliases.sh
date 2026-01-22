# ~/.bashrc: executed by bash(1) for non-login shells.

# ===== GENERAL SETTINGS =====
# Set default editor
export EDITOR='cursor'

# Shell history settings
HISTSIZE=10000
HISTFILESIZE=20000
HISTCONTROL=ignoreboth:erasedups

# Better ls options (uncomment to enable)
# export LS_OPTIONS='--color=auto'
# eval "$(dircolors)"
# alias ls='ls $LS_OPTIONS'
# alias ll='ls $LS_OPTIONS -l'
# alias l='ls $LS_OPTIONS -lA'

# Prevent accidental overwriting or deletion (uncomment to enable)
# alias rm='rm -i'
# alias cp='cp -i'
# alias mv='mv -i'

# ===== SHELL APPEARANCE =====
# Custom shell prompt with emojis 🚀
PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "

# ===== FREQTRADE ALIASES =====
# Main directories
alias ft='cd /allah/freqtrade'                   # Freqtrade root directory
alias ftcore='cd /allah/freqtrade/freqtrade'     # Freqtrade core directory
alias fq='cd /allah/blue/freq'                  # Freq directory
alias p1='cd /allah/blue/freq/project_1'        # Project 1 directory
alias p2='cd /allah/blue/freq/project_2'        # Project 2 directory

# Data & strategies
alias strat='cd /allah/blue/freq/project_1/user_data/strategies'  # Strategies directory
alias tv='cd /allah/blue/freq/misc/tradingview_scripts'          # TradingView scripts
alias mo='cd /allah/blue/freq/userdir/user_data/models'          # Models directory
alias usdt='cd /allah/freqtrade/user_data/data/binance/futures'   # Futures data directory
alias us='cd /allah/blue/freq/userdir/user_data'                 # User directory
alias label='cd /allah/blue/freq/project_2/labeled_data'         # Labeled data

# Run shortcuts
alias ftrun='/allah/freqtrade/.venv/bin/python3 /allah/freqtrade/freqtrade/main.py'
alias ftpy='/allah/freqtrade/.venv/bin/python3'

# ===== PROJECT DIRECTORIES =====
alias sf='cd /allah/blue/'                      # General blue directory
alias ml='cd /allah/blue/ml'                    # Machine Learning directory
alias ka='cd /allah/blue/ml/kaggle'             # Kaggle projects
alias web='cd /allah/blue/web'                  # Web projects
alias ba='cd /allah/blue/web/automation/baccarat'    # Baccarat project 
alias sm='cd /allah/blue/web/proxy/smartproxy'       # SmartProxy project
alias li='cd /allah/blue/linux/history'         # Linux history directory
alias dt='cd /allah/data/trades/eth_usdt_daily_trades'  # Trade data
alias pa='cd /allah/data/parquet'                # Parquet data directory

# ===== UTILITY ALIASES =====
# Code editors and configs
alias code='cursor'                              # Use cursor as code editor
alias bashrc='cursor ~/.bashrc'                  # Open .bashrc in editor
alias rc='cursor ~/.bashrc'                      # Shortcut to open .bashrc

# Git shortcuts
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git pull'

# Useful utilities
alias cls='clear'                                # Clear screen
alias lsh='ls -la | head'                        # List first 10 entries
alias diskspace='df -h'                          # Check disk space
alias myip='curl -s http://ipinfo.io/ip'         # Get public IP

# ===== ML & TENSORBOARD =====
alias lg='cd /allah/data/parquet/lightning_logs'                              # Lightning logs directory
alias tb='tensorboard --logdir "$(find . -type d -name "tensorboard" | sort | tail -n 1)"'  # Start TensorBoard
alias cdtb='cd "$(find . -type d -name "tensorboard" | sort | tail -n 1)"'                 # Navigate to TensorBoard logs

# ===== ENVIRONMENT VARIABLES =====
export DISPLAY=:10
export PATH="$HOME/development/flutter/bin:$PATH"
