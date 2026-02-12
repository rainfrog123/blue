#!/bin/bash
#
# Shared configuration for Decodo SmartProxy scripts
# Source this file in your scripts: source "$(dirname "$0")/../lib/config.sh"
#

# ============================================
# Credential Loading
# ============================================

# Credentials file path (relative to /allah/blue/)
CRED_FILE="/allah/blue/cred.json"

# Load credentials from environment variables or cred.json
load_credentials() {
    # Decodo proxy credentials
    DECODO_USERNAME="${DECODO_USERNAME:-user-sp3j58curv}"
    DECODO_PASSWORD="${DECODO_PASSWORD:-$(jq -r '.proxy.decodo.password' "$CRED_FILE" 2>/dev/null || echo 'SET_DECODO_PASSWORD_ENV')}"
    
    # IPQS API credentials
    IPQS_API_KEY="${IPQS_API_KEY:-$(jq -r '.ipqs.default_key' "$CRED_FILE" 2>/dev/null || echo 'SET_IPQS_API_KEY_ENV')}"
    
    export DECODO_USERNAME DECODO_PASSWORD IPQS_API_KEY
}

# ============================================
# Proxy Configuration
# ============================================

# Default proxy settings
PROXY_HOST_SOCKS5="gate.decodo.com"
PROXY_PORT_SOCKS5="7000"
PROXY_HOST_HTTPS="gate.decodo.com"
PROXY_PORT_HTTPS_MIN="10001"
PROXY_PORT_HTTPS_MAX="49999"

# API endpoints
DECODO_IP_API="https://ip.decodo.com/json"
IPQS_BASE_URL="https://ipqualityscore.com/api/json/ip"

# Default request settings
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# ============================================
# Helper Functions
# ============================================

# Get the project root directory
get_project_root() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    echo "$(dirname "$script_dir")"
}

# Get country name from country code
get_country_name() {
    local prefix="$1"
    local project_root="$(get_project_root)"
    local country_file="${project_root}/data/countries.txt"
    
    if [[ -f "$country_file" ]]; then
        local country_name=$(grep "'prefix': '$prefix'" "$country_file" | head -1 | sed -n "s/.*'location': '\([^']*\)'.*/\1/p")
        if [[ -n "$country_name" ]]; then
            echo "$country_name"
        else
            echo "$prefix"
        fi
    else
        echo "$prefix"
    fi
}

# Generate random session prefix
generate_session_prefix() {
    local fruits=("apple" "banana" "orange" "grape" "kiwi" "mango" "peach" "cherry" "lemon" "lime" "plum" "berry" "melon" "papaya")
    local chars=("a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z")
    
    local random_fruit=${fruits[$RANDOM % ${#fruits[@]}]}
    local random_nums=$(printf "%02d" $((RANDOM % 100)))
    local random_char1=${chars[$RANDOM % ${#chars[@]}]}
    local random_char2=${chars[$RANDOM % ${#chars[@]}]}
    local random_char3=${chars[$RANDOM % ${#chars[@]}]}
    
    echo "${random_fruit}${random_nums}${random_char1}${random_char2}${random_char3}"
}

# Get random port in HTTPS range
get_random_https_port() {
    echo $((PROXY_PORT_HTTPS_MIN + RANDOM % (PROXY_PORT_HTTPS_MAX - PROXY_PORT_HTTPS_MIN + 1)))
}

# Check for required tools
check_required_tools() {
    local tools=("$@")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required tools: ${missing[*]}"
        echo "Please install them before running this script."
        exit 1
    fi
}

# Print banner
print_banner() {
    local title="$1"
    echo "======================================"
    echo "$title"
    echo "======================================"
}

# Print emoji based on fraud score
get_score_emoji() {
    local score=$1
    if [[ "$score" -eq 0 ]]; then
        echo "✅✅✅"
    elif [[ "$score" -lt 20 ]]; then
        echo "✅✅"
    elif [[ "$score" -lt 40 ]]; then
        echo "✅"
    elif [[ "$score" -lt 70 ]]; then
        echo "⚠️"
    else
        echo "🚨"
    fi
}

# Auto-load credentials when sourced
load_credentials
