#!/bin/bash

# ========================================
# 📝 INSERT YOUR IP ADDRESS HERE:
# ========================================
# Examples:
# IPv4: TARGET_IP="8.8.8.8"
# IPv6: TARGET_IP="2a00:23c7:ffbd:9c00:2e99:75ff:fedb:7c2a"
TARGET_IP="94.177.14.241"

# IPQS Configuration - Load from environment or cred.json
IPQS_API_KEY="${IPQS_API_KEY:-$(jq -r '.ipqs.default_key' ~/Documents/cred.json 2>/dev/null || echo 'SET_IPQS_API_KEY_ENV')}"
IPQS_BASE_URL="https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}"
USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Check for required tools
if ! command -v jq &> /dev/null; then
    echo "❌ jq could not be found, please install it to run this script."
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "❌ curl could not be found, please install it to run this script."
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 [IP_ADDRESS]"
    echo "Example: $0 8.8.8.8"
    echo "Note: If no IP is provided, will use TARGET_IP from script"
    exit 1
}

# Use command line argument if provided, otherwise use TARGET_IP
if [ $# -eq 0 ]; then
    if [ -z "$TARGET_IP" ]; then
        echo "❌ TARGET_IP is empty and no command line argument provided."
        echo "Please set TARGET_IP in the script or provide IP as argument."
        usage
    fi
    IP_ADDRESS="$TARGET_IP"
    echo "ℹ️  Using TARGET_IP from script: $IP_ADDRESS"
else
    IP_ADDRESS="$1"
    echo "ℹ️  Using command line argument: $IP_ADDRESS"
fi

# Validate IP address format (IPv4 and IPv6)
validate_ip() {
    local ip="$1"
    
    # IPv4 validation
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Check each octet is between 0-255
        IFS='.' read -ra OCTETS <<< "$ip"
        for octet in "${OCTETS[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    
    # IPv6 validation (basic check for colon-separated hex groups)
    if [[ $ip =~ ^[0-9a-fA-F:]+$ ]] && [[ $ip == *:* ]]; then
        # Basic IPv6 format check - contains colons and hex characters
        return 0
    fi
    
    return 1
}

if ! validate_ip "$IP_ADDRESS"; then
    echo "❌ Invalid IP address format: $IP_ADDRESS"
    echo "Supported formats: IPv4 (e.g., 192.168.1.1) and IPv6 (e.g., 2001:db8::1)"
    exit 1
fi

echo "====================================== 🔍"
echo "IPQS IP Analysis for: $IP_ADDRESS"
echo "======================================"

# Make API call to IPQS
URL="${IPQS_BASE_URL}/${IP_ADDRESS}"
RESPONSE=$(curl -s "$URL" \
    --get \
    --data-urlencode "strictness=3" \
    --data-urlencode "user_agent=$USER_AGENT" \
    --data-urlencode "user_language=en-US" \
    --data-urlencode "fast=false" \
    --data-urlencode "mobile=false")

# Check if curl was successful
if [ $? -ne 0 ]; then
    echo "❌ Failed to connect to IPQS API"
    exit 1
fi

# Check if API response is successful
SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
if [ "$SUCCESS" != "true" ]; then
    ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.message // "Unknown error"')
    echo "❌ API Error: $ERROR_MESSAGE"
    exit 1
fi

# Extract all information from the response
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

# Function to format boolean with emoji
format_bool() {
    if [ "$1" = "true" ]; then
        echo "✅ Yes"
    elif [ "$1" = "false" ]; then
        echo "❌ No"
    else
        echo "❓ $1"
    fi
}

# Function to get fraud score emoji
get_fraud_emoji() {
    local score=$1
    if [ "$score" = "N/A" ]; then
        echo "❓"
    elif [ "$score" -eq 0 ]; then
        echo "✅✅✅"
    elif [ "$score" -lt 20 ]; then
        echo "✅✅"
    elif [ "$score" -lt 40 ]; then
        echo "✅"
    elif [ "$score" -lt 70 ]; then
        echo "⚠️"
    else
        echo "🚨"
    fi
}

# Display comprehensive results
echo ""
echo "🎯 FRAUD ANALYSIS"
echo "-------------------"
echo "Fraud Score:       $(get_fraud_emoji "$FRAUD_SCORE") $FRAUD_SCORE/100"
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
echo "====================================== 🔍"
echo "Analysis completed for: $IP_ADDRESS"
echo "======================================"