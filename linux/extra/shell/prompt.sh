# ~/.bashrc: Configuration file executed by Bash(1) for non-login shells.

# Additional aliases for safer commands and common tasks.
# alias rm='rm -i'
# alias cp='cp -i'
# alias mv='mv -i'

# Customize the command prompt (PS1) with different color and emoji combinations.
# Note: PS1 and umask are already set in /etc/profile. Uncomment if different defaults for root are desired.
# PS1='${debian_chroot:+($debian_chroot)}\h:\w\$ '
# umask 022

# PS1="\[\033[1;36m\]\u\[\033[0m\]@\[\033[1;35m\]\h\[\033[0m\] \[\e[1;35m\]\w\[\e[0m\] 🌟🌙🔥  $ "
PS1="\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\e[1;34m\]\w\[\e[0m\] 🚀🚀🚀  $ "

# cd /allah/freqtrade

alias japan='ssh root@172.232.237.204'
alias strat='cd /allah/freqtrade/user_data/strategies'
alias ft='cd /allah/freqtrade'
alias data='cd /allah/freqtrade/user_data/data/binance/futures'
alias feather='cd /allah/freqtrade/orange_project/aggTrades/feather_data'
alias json='cd /allah/freqtrade/orange_project/json_files'
alias actenv='source /allah/freqtrade/.venv/bin/activate'
alias freq='cd /allah/blue/freq'
alias linux='cd /allah/blue/linux'
alias tv='cd /allah/blue/freq/tradingview'
alias ml='cd /allah/blue/ml'
alias bot='cd /allah/blue/freq/bot_2_ML_1m_bot'
alias damai='cd /allah/blue/damai'
alias ft1sec='cd /allah/blue/freq/bot_1/ft_1s_version'
alias bashrc='code ~/.bashrc'
alias orange='cd /allah/freqtrade/orange_project'
alias plot='cd /allah/freqtrade/user_data/plot/'
alias stuff='cd /allah/blue'
alias book='cd /allah/blue/ml/book'
alias dujiao='cd ~/website_data/edgesoftware.xyz/dujiaoka'
alias hub='cd /allah/blue/linux/docker/unicorn-hub'




export LS_OPTIONS='--color=auto'
eval "$(dircolors)"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'