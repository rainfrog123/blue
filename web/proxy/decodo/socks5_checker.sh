#!/bin/bash

# SmartProxy Configuration - Load from environment or cred.json
base_url="https://ip.decodo.com/json"
# Load credentials from environment variables or use defaults
username="${DECODO_USERNAME:-user-sp3j58curv}"
password="${DECODO_PASSWORD:-$(jq -r '.proxy.decodo.password' ~/Documents/cred.json 2>/dev/null || echo 'SET_DECODO_PASSWORD_ENV')}"
proxy_server="gate.decodo.com:7000"
session_duration="60"  # in minutes (1-1440)
country="dk"           # two-letter country code
# city="Hamburg"         # city name (use underscores for spaces)
# state=""            # state code (for US - use us_state_name format)
# continent=""        # continent code (eu, na, as, sa, af, oc)
# asn=""              # ASN number

# Session prefix (p = persistent, r = random)
fruits=("apple" "banana" "orange" "grape" "kiwi" "mango" "peach" "cherry" "lemon" "lime" "plum" "berry" "melon" "papaya")
chars=("a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z")
random_fruit=${fruits[$RANDOM % ${#fruits[@]}]}
random_nums=$(printf "%02d" $((RANDOM % 100)))
random_char1=${chars[$RANDOM % ${#chars[@]}]}
random_char2=${chars[$RANDOM % ${#chars[@]}]}
random_char3=${chars[$RANDOM % ${#chars[@]}]}
session_prefix="${random_fruit}${random_nums}${random_char1}${random_char2}${random_char3}"

# Define number of sessions to test
num_sessions=10

# IPQS Configuration - Load from environment or cred.json
ipqs_api_key="${IPQS_API_KEY:-$(jq -r '.ipqs.default_key' ~/Documents/cred.json 2>/dev/null || echo 'SET_IPQS_API_KEY_ENV')}"
ipqs_base_url="https://ipqualityscore.com/api/json/ip/${ipqs_api_key}"
user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Maximum number of concurrent processes
max_concurrent=10

# Check for required tools
if ! command -v jq &> /dev/null; then
    echo "jq could not be found, please install it to run this script."
    exit 1
fi

# Build the authentication string based on configured parameters
build_auth_string() {
    local session_name=$1
    local auth_string="${username}"
    
    # Add session parameters first
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
    
    echo "${auth_string}:${password}"
}

# Create a temporary directory for results
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Initialize arrays and associative array for proxy links
declare -a ip_list
declare -a city_list
declare -a country_list
declare -A proxy_links
declare -A session_to_ip
declare -A fraud_scores
declare -a clean_ips

echo "====================================== 🚀🚀🚀"
echo "Decodo SmartProxy IP Checker (Async Mode)"
echo "======================================"
echo "Proxy server: $proxy_server"
if [[ -n "$city" ]]; then
    echo "Location: $city, $country"
else
    echo "Location: $country"
fi
echo "Session duration: $session_duration minutes"
echo "Sessions to test: $num_sessions"
echo "Max concurrent: $max_concurrent"
echo "======================================"

echo "Phase 1: Collecting IPs from SmartProxy..."

# Function to test a single session
test_session() {
    local session="$1"
    local result_file="$2"
    
    local auth_string=$(build_auth_string "$session")
    local response=$(curl -s -x "socks5h://${auth_string}@${proxy_server}" "${base_url}")
    
    if [ $? -eq 0 ]; then
        local ip=$(echo $response | jq -r '.proxy.ip')
        local city=$(echo $response | jq -r '.city.name')
        local country_code=$(echo $response | jq -r '.country.code')
        local country_name=$(echo $response | jq -r '.country.name')
        
        if [ "$ip" != "null" ]; then
            # Write results to temp file
            echo "${session}|${ip}|${city}|${country_code}|${country_name}|${auth_string}" > "$result_file"
            echo "OK - $session: $ip ($city)"
        else
            echo "Failed to get IP for session $session"
        fi
    else
        echo "Failed to connect for session $session"
    fi
}

# Launch session tests in parallel with a limit on concurrent processes
active_procs=0
for i in $(seq 1 $num_sessions); do
    session="${session_prefix}$i"
    result_file="${TEMP_DIR}/session_${session}.result"
    
    # Launch in background
    test_session "$session" "$result_file" &
    
    # Count active processes and limit if necessary
    active_procs=$((active_procs + 1))
    if (( active_procs >= max_concurrent )); then
        wait -n  # Wait for any child process to finish
        active_procs=$((active_procs - 1))
    fi
done

# Wait for all remaining processes to complete
wait

echo "All session tests completed. Processing results..."

# Process results from temporary files
for result_file in "${TEMP_DIR}"/session_*.result; do
    if [ -f "$result_file" ]; then
        IFS='|' read -r session ip city country_code country_name auth_string < "$result_file"
        
        # Check if this IP is already in our list
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
            # Store the proxy details and session name
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
    
    local url="${ipqs_base_url}/${ip}"
    local response=$(curl -s "$url" \
        --get \
        --data-urlencode "strictness=3" \
        --data-urlencode "user_agent=$user_agent" \
        --data-urlencode "user_language=en-US")

    if [ $? -eq 0 ]; then
        local success=$(echo "$response" | jq -r '.success')
        if [ "$success" = "true" ]; then
            local fraud_score=$(echo "$response" | jq -r '.fraud_score')
            # Write result to temp file
            echo "${ip}|${fraud_score}" > "$result_file"
        else
            local error_message=$(echo "$response" | jq -r '.message')
            echo "IP: $ip - API error: $error_message"
        fi
    else
        echo "IP: $ip - Failed to connect to IPQS API"
    fi
}

# Launch IP checks in parallel with a limit on concurrent processes
active_procs=0
for ip in "${ip_list[@]}"; do
    result_file="${TEMP_DIR}/ip_${ip}.result"
    
    # Launch in background
    check_ip "$ip" "$result_file" &
    
    # Count active processes and limit if necessary
    active_procs=$((active_procs + 1))
    if (( active_procs >= max_concurrent )); then
        wait -n  # Wait for any child process to finish
        active_procs=$((active_procs - 1))
    fi
    
    # Add a small delay to avoid hitting API rate limits
    sleep 0.2
done

# Wait for all remaining processes to complete
wait

echo "All IP checks completed. Processing results..."

# Process results from temporary files
for result_file in "${TEMP_DIR}"/ip_*.result; do
    if [ -f "$result_file" ]; then
        IFS='|' read -r ip fraud_score < "$result_file"
        fraud_scores["$ip"]=$fraud_score
        
        # Find the index of this IP in ip_list to get corresponding city and country
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
        
        # Print minimal info with score
        printf "IP: %-45s Score: %3d - %s (Sessions: %s)\n" "$ip" "$fraud_score" "$city" "$sessions_with_ip"
        
        # If fraud score is less than 50, add to clean IPs array
        if [ "$fraud_score" -lt 50 ]; then
            clean_ips+=("$ip")
        fi
    fi
done

echo -e "\n====================================== 🚀🚀🚀"
echo "Ranked Clean IPs by Fraud Score"
echo "======================================"

# Sort and display clean IPs by fraud score
if [ ${#clean_ips[@]} -gt 0 ]; then
    # Sort clean_ips by fraud_score (low to high)
    IFS=$'\n' sorted_ips=($(
        for ip in "${clean_ips[@]}"; do
            echo "$ip ${fraud_scores[$ip]}"
        done | sort -k2n | awk '{print $1}'
    ))
    unset IFS
    
    # Display sorted clean IPs
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
        
        # Get proxy link
        link="${proxy_links[$ip]}"
        
        # Print with emojis based on score
        if [ "$score" -eq 0 ]; then
            emoji="✅✅✅"
        elif [ "$score" -lt 20 ]; then
            emoji="✅✅"
        elif [ "$score" -lt 40 ]; then
            emoji="✅"
        else
            emoji="⚠️"
        fi
        
        echo "$emoji Score: $score - IP: $ip ($city, Session: $session)"
        echo "socks5h://$link@gate.decodo.com:7000"
    done
    
    # Print the final best link
    if [ ${#sorted_ips[@]} -gt 0 ]; then
        best_ip=${sorted_ips[0]}
        best_link="${proxy_links[$best_ip]}"
        echo -e "\n====================================== 🚀🚀🚀"
        echo "Best Proxy Connection:"
        echo "======================================"
        echo "socks5h://$best_link@gate.decodo.com:7000"
    fi
else
    echo "No clean IPs found (score < 50)"
fi 