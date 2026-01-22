#!/bin/bash

# Oculus SOCKS5 Proxy Tester - Bash Version
# Tests 20 different sessions to get different UK IPs

echo "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀"
echo "Oculus SOCKS5 Proxy Tester (Bash)"
echo "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀"
echo "Plan: SHARED_DC (Direct SOCKS5)"
echo "Country: UK"
echo "Sessions to test: 20"
echo "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀"
echo

# Proxy configuration - Load from environment or cred.json
PROXY_BASE="${RAYOBYTE_USERNAME:-oc-07236915a7657ef469271111c065c3297dca127e972f4b9d710c78ead9d4f872}-country-UK-session"
PROXY_PASSWORD="${RAYOBYTE_PASSWORD:-$(jq -r '.proxy.rayobyte.password' ~/Documents/cred.json 2>/dev/null || echo 'SET_RAYOBYTE_PASSWORD_ENV')}"
PROXY_SERVER="proxy.oculus-proxy.com"
PROXY_PORT="31115"

# IPQS API configuration - Load from environment or cred.json
IPQS_API_KEY="${IPQS_API_KEY:-$(jq -r '.ipqs.default_key' ~/Documents/cred.json 2>/dev/null || echo 'SET_IPQS_API_KEY_ENV')}"
IPQS_BASE_URL="https://ipqualityscore.com/api/json/ip/${IPQS_API_KEY}"

# Function to check IP fraud score
check_fraud_score() {
    local ip="$1"
    local response=$(curl -s "${IPQS_BASE_URL}/${ip}" \
        --get \
        --data-urlencode "strictness=3" \
        --data-urlencode "fast=true" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        local success=$(echo "$response" | grep -o '"success": *true' 2>/dev/null)
        if [ -n "$success" ]; then
            local score=$(echo "$response" | grep -o '"fraud_score": *[0-9]*' | grep -o '[0-9]*' 2>/dev/null)
            echo "${score:-100}"
            return 0
        fi
    fi
    echo "100"  # Default high score on error
}

# Function to get fraud score emoji
get_fraud_emoji() {
    local score=$1
    if [ "$score" -eq 0 ]; then
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

# Arrays to store results
working_ips=()
working_sessions=()
fraud_scores=()

echo "🔍 Testing 20 different proxy sessions..."
echo

# Test 20 random session numbers
for i in {1..20}; do
    # Generate random session number between 100-9999
    session=$((100 + RANDOM % 9899))
    
    # Build proxy URL
    proxy_url="socks5h://${PROXY_BASE}-${session}:${PROXY_PASSWORD}@${PROXY_SERVER}:${PROXY_PORT}"
    
    # Test proxy
    printf "%2d. Testing Session-%-4d: " "$i" "$session"
    
    # Use curl to test the proxy with 10 second timeout
    result=$(curl -x "$proxy_url" -s --max-time 10 http://httpbin.org/ip 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$result" ]; then
        # Extract IP from JSON response
        ip=$(echo "$result" | grep -o '"origin": "[^"]*"' | cut -d'"' -f4)
        
        if [ -n "$ip" ]; then
            # Check fraud score
            printf "✅ %-15s " "$ip"
            fraud_score=$(check_fraud_score "$ip")
            emoji=$(get_fraud_emoji "$fraud_score")
            printf "Score: %s %s\n" "$emoji" "$fraud_score"
            
            working_ips+=("$ip")
            working_sessions+=("$session")
            fraud_scores+=("$fraud_score")
        else
            echo "❌ Invalid response"
        fi
    else
        echo "❌ Connection failed"
    fi
done

echo
echo "📊 SUMMARY:"
echo "Total tested: 20"
echo "Working proxies: ${#working_ips[@]}"
echo

if [ ${#working_ips[@]} -gt 0 ]; then
    echo "✅ Working IPs with Fraud Scores:"
    echo "=================================="
    
    # Create arrays with indices sorted by fraud score
    indices=($(for i in "${!fraud_scores[@]}"; do echo "$i:${fraud_scores[i]}"; done | sort -t: -k2 -n | cut -d: -f1))
    
    for idx in "${!indices[@]}"; do
        i="${indices[idx]}"
        emoji=$(get_fraud_emoji "${fraud_scores[i]}")
        printf "%2d. %s Score: %2d - Session-%-4d -> %s\n" "$((idx+1))" "$emoji" "${fraud_scores[i]}" "${working_sessions[i]}" "${working_ips[i]}"
    done
    echo
    
    # Save results to file (sorted by fraud score)
    echo "💾 Saving results to oculus_working_sessions.txt..."
    {
        echo "# Oculus SOCKS5 Working Sessions - $(date)"
        echo "# Format: Session-Number -> IP-Address (Fraud Score)"
        echo "# Sorted by fraud score (lowest = best)"
        echo
        for idx in "${!indices[@]}"; do
            i="${indices[idx]}"
            emoji=$(get_fraud_emoji "${fraud_scores[i]}")
            printf "Session-%-4d -> %-15s %s Score: %2d\n" "${working_sessions[i]}" "${working_ips[i]}" "$emoji" "${fraud_scores[i]}"
        done
    } > oculus_working_sessions.txt
    
    echo "✅ Results saved!"
    
    # Show best session (lowest fraud score)
    best_idx="${indices[0]}"
    best_emoji=$(get_fraud_emoji "${fraud_scores[best_idx]}")
    echo
    echo "🏆 BEST SESSION (Lowest Fraud Score):"
    echo "====================================="
    echo "Session: ${working_sessions[best_idx]}"
    echo "IP: ${working_ips[best_idx]}"
    echo "Fraud Score: $best_emoji ${fraud_scores[best_idx]}"
    echo "Full Command:"
    echo "curl -x socks5h://${PROXY_BASE}-${working_sessions[best_idx]}:${PROXY_PASSWORD}@${PROXY_SERVER}:${PROXY_PORT} http://httpbin.org/ip"
else
    echo "❌ No working proxies found!"
fi

echo
echo "🎯 Test completed!"
