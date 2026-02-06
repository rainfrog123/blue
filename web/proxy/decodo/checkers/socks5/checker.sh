#!/bin/bash
#
# Decodo SmartProxy SOCKS5 Checker
# Tests multiple proxy sessions and checks IPs with IPQS fraud scoring
#

# Load shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/config.sh"

# Check required tools
check_required_tools jq curl

# ============================================
# Configuration
# ============================================

session_duration="60"   # in minutes (1-1440)
country="dk"            # two-letter country code
# city="Hamburg"        # city name (use underscores for spaces)
# state=""              # state code (for US - use us_state_name format)
# continent=""          # continent code (eu, na, as, sa, af, oc)
# asn=""                # ASN number

# Session prefix (randomly generated)
session_prefix="$(generate_session_prefix)"

# Number of sessions to test
num_sessions=10

# Maximum concurrent processes
max_concurrent=10

# ============================================
# Build Authentication String
# ============================================

build_auth_string() {
    local session_name=$1
    local auth_string="${DECODO_USERNAME}"
    
    # Add session parameters
    auth_string="${auth_string}-session-${session_name}"
    auth_string="${auth_string}-sessionduration-${session_duration}"
    
    # Add location parameters (in priority order)
    if [[ -n "$continent" ]]; then
        auth_string="${auth_string}-continent-${continent}"
    elif [[ -n "$country" ]]; then
        auth_string="${auth_string}-country-${country}"
        
        if [[ -n "$state" ]]; then
            auth_string="${auth_string}-state-${state}"
        elif [[ -n "$city" ]]; then
            auth_string="${auth_string}-city-${city}"
        fi
    fi
    
    # Add ASN if specified (cannot be combined with city)
    if [[ -n "$asn" && -z "$city" ]]; then
        auth_string="${auth_string}-asn-${asn}"
    fi
    
    echo "${auth_string}:${DECODO_PASSWORD}"
}

# ============================================
# Main Script
# ============================================

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Initialize arrays
declare -a ip_list
declare -a city_list
declare -a country_list
declare -A proxy_links
declare -A session_to_ip
declare -A fraud_scores
declare -a clean_ips

print_banner "Decodo SmartProxy SOCKS5 Checker"
echo "Proxy server: ${PROXY_HOST_SOCKS5}:${PROXY_PORT_SOCKS5}"

country_full=$(get_country_name "$country")
if [[ -n "$city" ]]; then
    echo "Location: $city, $country_full"
else
    echo "Location: $country_full"
fi

echo "Session duration: $session_duration minutes"
echo "Sessions to test: $num_sessions"
echo "Max concurrent: $max_concurrent"
echo "======================================"

echo -e "\nPhase 1: Collecting IPs from SmartProxy..."

# Function to test a single session
test_session() {
    local session="$1"
    local result_file="$2"
    
    local auth_string=$(build_auth_string "$session")
    local proxy_url="socks5h://${auth_string}@${PROXY_HOST_SOCKS5}:${PROXY_PORT_SOCKS5}"
    local response=$(curl -s -x "$proxy_url" "${DECODO_IP_API}")
    
    if [ $? -eq 0 ]; then
        local ip=$(echo $response | jq -r '.proxy.ip')
        local city=$(echo $response | jq -r '.city.name')
        local country_code=$(echo $response | jq -r '.country.code')
        local country_name=$(echo $response | jq -r '.country.name')
        
        if [ "$ip" != "null" ]; then
            echo "${session}|${ip}|${city}|${country_code}|${country_name}|${auth_string}" > "$result_file"
            echo "OK - $session: $ip ($city)"
        else
            echo "Failed to get IP for session $session"
        fi
    else
        echo "Failed to connect for session $session"
    fi
}

# Launch session tests in parallel with concurrency limit
active_procs=0
for i in $(seq 1 $num_sessions); do
    session="${session_prefix}$i"
    result_file="${TEMP_DIR}/session_${session}.result"
    
    test_session "$session" "$result_file" &
    
    active_procs=$((active_procs + 1))
    if (( active_procs >= max_concurrent )); then
        wait -n
        active_procs=$((active_procs - 1))
    fi
done

wait
echo "All session tests completed. Processing results..."

# Process results from temporary files
for result_file in "${TEMP_DIR}"/session_*.result; do
    if [ -f "$result_file" ]; then
        IFS='|' read -r session ip city country_code country_name auth_string < "$result_file"
        
        # Check for duplicates
        duplicate=false
        for existing_ip in "${ip_list[@]}"; do
            if [[ "$existing_ip" == "$ip" ]]; then
                duplicate=true
                echo "DUPLICATE IP: $ip (Session: $session)"
                break
            fi
        done
        
        if ! $duplicate; then
            ip_list+=("$ip")
            city_list+=("$city")
            country_list+=("$country_name")
            clean_cmd=$(echo "${auth_string}" | sed 's/"//g')
            proxy_links["$ip"]="$clean_cmd"
            session_to_ip["$session"]="$ip"
        fi
    fi
done

echo -e "\nPhase 2: Checking IPs with IPQS..."

# Function to check a single IP
check_ip() {
    local ip="$1"
    local result_file="$2"
    
    local url="${IPQS_BASE_URL}/${IPQS_API_KEY}/${ip}"
    local response=$(curl -s "$url" \
        --get \
        --data-urlencode "strictness=3" \
        --data-urlencode "user_agent=$USER_AGENT" \
        --data-urlencode "user_language=en-US")

    if [ $? -eq 0 ]; then
        local success=$(echo "$response" | jq -r '.success')
        if [ "$success" = "true" ]; then
            local fraud_score=$(echo "$response" | jq -r '.fraud_score')
            echo "${ip}|${fraud_score}" > "$result_file"
        else
            local error_message=$(echo "$response" | jq -r '.message')
            echo "IP: $ip - API error: $error_message"
        fi
    else
        echo "IP: $ip - Failed to connect to IPQS API"
    fi
}

# Launch IP checks in parallel
active_procs=0
for ip in "${ip_list[@]}"; do
    result_file="${TEMP_DIR}/ip_${ip}.result"
    
    check_ip "$ip" "$result_file" &
    
    active_procs=$((active_procs + 1))
    if (( active_procs >= max_concurrent )); then
        wait -n
        active_procs=$((active_procs - 1))
    fi
    
    sleep 0.2  # Rate limiting
done

wait
echo "All IP checks completed. Processing results..."

# Process IP check results
for result_file in "${TEMP_DIR}"/ip_*.result; do
    if [ -f "$result_file" ]; then
        IFS='|' read -r ip fraud_score < "$result_file"
        fraud_scores["$ip"]=$fraud_score
        
        # Find corresponding city and country
        for i in "${!ip_list[@]}"; do
            if [[ "${ip_list[$i]}" = "${ip}" ]]; then
                city="${city_list[$i]}"
                country="${country_list[$i]}"
                break
            fi
        done
        
        # Find session names associated with this IP
        sessions_with_ip=""
        for session in "${!session_to_ip[@]}"; do
            if [[ "${session_to_ip[$session]}" == "$ip" ]]; then
                if [[ -z "$sessions_with_ip" ]]; then
                    sessions_with_ip="$session"
                else
                    sessions_with_ip="$sessions_with_ip, $session"
                fi
            fi
        done
        
        printf "IP: %-45s Score: %3d - %s (Sessions: %s)\n" "$ip" "$fraud_score" "$city" "$sessions_with_ip"
        
        if [ "$fraud_score" -lt 50 ]; then
            clean_ips+=("$ip")
        fi
    fi
done

echo ""
print_banner "Ranked Clean IPs by Fraud Score"

# Sort and display clean IPs
if [ ${#clean_ips[@]} -gt 0 ]; then
    IFS=$'\n' sorted_ips=($(
        for ip in "${clean_ips[@]}"; do
            echo "$ip ${fraud_scores[$ip]}"
        done | sort -k2n | awk '{print $1}'
    ))
    unset IFS
    
    for ip in "${sorted_ips[@]}"; do
        score=${fraud_scores[$ip]}
        
        # Find session for this IP
        session=""
        for s in "${!session_to_ip[@]}"; do
            if [[ "${session_to_ip[$s]}" == "$ip" ]]; then
                session=$s
                break
            fi
        done
        
        # Find city for this IP
        city=""
        for i in "${!ip_list[@]}"; do
            if [[ "${ip_list[$i]}" = "${ip}" ]]; then
                city="${city_list[$i]}"
                break
            fi
        done
        
        link="${proxy_links[$ip]}"
        emoji=$(get_score_emoji "$score")
        
        echo "$emoji Score: $score - IP: $ip ($city, Session: $session)"
        echo "socks5h://$link@${PROXY_HOST_SOCKS5}:${PROXY_PORT_SOCKS5}"
    done
    
    # Print best proxy
    if [ ${#sorted_ips[@]} -gt 0 ]; then
        best_ip=${sorted_ips[0]}
        best_link="${proxy_links[$best_ip]}"
        echo ""
        print_banner "Best Proxy Connection"
        echo "socks5h://$best_link@${PROXY_HOST_SOCKS5}:${PROXY_PORT_SOCKS5}"
    fi
else
    echo "No clean IPs found (score < 50)"
fi
