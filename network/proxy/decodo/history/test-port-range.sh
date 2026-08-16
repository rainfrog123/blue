#!/bin/bash
#
# Port Range Tester for Decodo SmartProxy
# Tests a range of HTTPS proxy ports to check availability
#

# Load shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/config.sh"

# Check required tools
check_required_tools curl

# ============================================
# Configuration
# ============================================

# Port range to test
PORT_START=${1:-45000}
PORT_END=${2:-45100}

# Test URL
TEST_URL="https://www.google.com/search?q=test"

# Session configuration
session_duration="60"
country="gb"

# ============================================
# Main Script
# ============================================

print_banner "Testing ports $PORT_START-$PORT_END"
echo "Port | Status"
echo "----------"

# Build auth string
auth_string="${DECODO_USERNAME}-sessionduration-${session_duration}-country-${country}:${DECODO_PASSWORD}"

for port in $(seq $PORT_START $PORT_END); do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -A "$USER_AGENT" \
        -x "https://${auth_string}@${PROXY_HOST_HTTPS}:${port}" \
        --connect-timeout 10 \
        --max-time 15 \
        "$TEST_URL")
    
    if [[ "$status" == "200" ]]; then
        echo "$port | $status ✅"
    elif [[ "$status" == "000" ]]; then
        echo "$port | $status (timeout/error)"
    else
        echo "$port | $status"
    fi
done
