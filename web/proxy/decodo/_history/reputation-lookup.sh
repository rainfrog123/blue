#!/bin/bash
#
# IP Reputation Checker using IPQS
# Check the fraud score and other details for any IP address
#

# Load shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/config.sh"

# Check required tools
check_required_tools jq curl

# ============================================
# Configuration
# ============================================

# Default target IP (can be overridden by command line argument)
TARGET_IP="94.177.14.241"

# ============================================
# Functions
# ============================================

usage() {
    echo "Usage: $0 [IP_ADDRESS]"
    echo "Example: $0 8.8.8.8"
    echo "Note: If no IP is provided, will use TARGET_IP from script"
    exit 1
}

validate_ip() {
    local ip="$1"
    
    # IPv4 validation
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra OCTETS <<< "$ip"
        for octet in "${OCTETS[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    
    # IPv6 validation (basic check)
    if [[ $ip =~ ^[0-9a-fA-F:]+$ ]] && [[ $ip == *:* ]]; then
        return 0
    fi
    
    return 1
}

format_bool() {
    if [ "$1" = "true" ]; then
        echo "✅ Yes"
    elif [ "$1" = "false" ]; then
        echo "❌ No"
    else
        echo "❓ $1"
    fi
}

# ============================================
# Main Script
# ============================================

# Use command line argument if provided
if [ $# -eq 0 ]; then
    if [ -z "$TARGET_IP" ]; then
        echo "❌ TARGET_IP is empty and no command line argument provided."
        usage
    fi
    IP_ADDRESS="$TARGET_IP"
    echo "ℹ️  Using TARGET_IP from script: $IP_ADDRESS"
else
    IP_ADDRESS="$1"
    echo "ℹ️  Using command line argument: $IP_ADDRESS"
fi

# Validate IP
if ! validate_ip "$IP_ADDRESS"; then
    echo "❌ Invalid IP address format: $IP_ADDRESS"
    echo "Supported formats: IPv4 (e.g., 192.168.1.1) and IPv6 (e.g., 2001:db8::1)"
    exit 1
fi

print_banner "IPQS IP Analysis for: $IP_ADDRESS"

# Make API call
URL="${IPQS_BASE_URL}/${IPQS_API_KEY}/${IP_ADDRESS}"
RESPONSE=$(curl -s "$URL" \
    --get \
    --data-urlencode "strictness=3" \
    --data-urlencode "user_agent=$USER_AGENT" \
    --data-urlencode "user_language=en-US" \
    --data-urlencode "fast=false" \
    --data-urlencode "mobile=false")

if [ $? -ne 0 ]; then
    echo "❌ Failed to connect to IPQS API"
    exit 1
fi

# Check API response
SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
if [ "$SUCCESS" != "true" ]; then
    ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.message // "Unknown error"')
    echo "❌ API Error: $ERROR_MESSAGE"
    exit 1
fi

# Extract information
FRAUD_SCORE=$(echo "$RESPONSE" | jq -r '.fraud_score // "N/A"')
COUNTRY_CODE=$(echo "$RESPONSE" | jq -r '.country_code // "N/A"')
REGION=$(echo "$RESPONSE" | jq -r '.region // "N/A"')
CITY=$(echo "$RESPONSE" | jq -r '.city // "N/A"')
ZIP_CODE=$(echo "$RESPONSE" | jq -r '.zip_code // "N/A"')
LATITUDE=$(echo "$RESPONSE" | jq -r '.latitude // "N/A"')
LONGITUDE=$(echo "$RESPONSE" | jq -r '.longitude // "N/A"')
TIMEZONE=$(echo "$RESPONSE" | jq -r '.timezone // "N/A"')
ISP=$(echo "$RESPONSE" | jq -r '.ISP // "N/A"')
ASN=$(echo "$RESPONSE" | jq -r '.ASN // "N/A"')
ORGANIZATION=$(echo "$RESPONSE" | jq -r '.organization // "N/A"')
IS_CRAWLER=$(echo "$RESPONSE" | jq -r '.is_crawler // "N/A"')
CONNECTION_TYPE=$(echo "$RESPONSE" | jq -r '.connection_type // "N/A"')
ABUSE_VELOCITY=$(echo "$RESPONSE" | jq -r '.abuse_velocity // "N/A"')

# Boolean flags
PROXY=$(echo "$RESPONSE" | jq -r '.proxy // false')
VPN=$(echo "$RESPONSE" | jq -r '.vpn // false')
TOR=$(echo "$RESPONSE" | jq -r '.tor // false')
ACTIVE_VPN=$(echo "$RESPONSE" | jq -r '.active_vpn // false')
ACTIVE_TOR=$(echo "$RESPONSE" | jq -r '.active_tor // false')
RECENT_ABUSE=$(echo "$RESPONSE" | jq -r '.recent_abuse // false')
BOT_STATUS=$(echo "$RESPONSE" | jq -r '.bot_status // false')
MOBILE=$(echo "$RESPONSE" | jq -r '.mobile // false')

# Display results
echo ""
echo "🎯 FRAUD ANALYSIS"
echo "-------------------"
echo "Fraud Score:       $(get_score_emoji "$FRAUD_SCORE") $FRAUD_SCORE/100"
echo "Recent Abuse:      $(format_bool "$RECENT_ABUSE")"
echo "Abuse Velocity:    $ABUSE_VELOCITY"
echo ""

echo "🌐 LOCATION INFORMATION"
echo "----------------------"
echo "Country:          $COUNTRY_CODE"
echo "Region/State:     $REGION"
echo "City:             $CITY"
echo "ZIP Code:         $ZIP_CODE"
echo "Latitude:         $LATITUDE"
echo "Longitude:        $LONGITUDE"
echo "Timezone:         $TIMEZONE"
echo ""

echo "🔌 NETWORK INFORMATION"
echo "---------------------"
echo "ISP:              $ISP"
echo "ASN:              $ASN"
echo "Organization:     $ORGANIZATION"
echo "Connection Type:  $CONNECTION_TYPE"
echo ""

echo "🔒 PROXY/VPN DETECTION"
echo "---------------------"
echo "Proxy:            $(format_bool "$PROXY")"
echo "VPN:              $(format_bool "$VPN")"
echo "Active VPN:       $(format_bool "$ACTIVE_VPN")"
echo "TOR:              $(format_bool "$TOR")"
echo "Active TOR:       $(format_bool "$ACTIVE_TOR")"
echo ""

echo "🤖 BOT/CRAWLER DETECTION"
echo "------------------------"
echo "Bot Status:       $(format_bool "$BOT_STATUS")"
echo "Is Crawler:       $(format_bool "$IS_CRAWLER")"
echo "Mobile:           $(format_bool "$MOBILE")"
echo ""

# Risk assessment
echo "📊 RISK ASSESSMENT"
echo "------------------"
if [ "$FRAUD_SCORE" != "N/A" ]; then
    if [ "$FRAUD_SCORE" -eq 0 ]; then
        echo "Risk Level:       🟢 VERY LOW (Excellent)"
    elif [ "$FRAUD_SCORE" -lt 20 ]; then
        echo "Risk Level:       🟢 LOW (Good)"
    elif [ "$FRAUD_SCORE" -lt 40 ]; then
        echo "Risk Level:       🟡 MODERATE (Acceptable)"
    elif [ "$FRAUD_SCORE" -lt 70 ]; then
        echo "Risk Level:       🟠 HIGH (Caution)"
    else
        echo "Risk Level:       🔴 VERY HIGH (Dangerous)"
    fi
else
    echo "Risk Level:       ❓ Unknown"
fi

echo ""
print_banner "Analysis completed for: $IP_ADDRESS"
