#!/bin/bash
#
# Decodo SmartProxy HTTPS Checker
# Tests multiple proxy sessions and checks IPs with IPQS fraud scoring
#

set -euo pipefail

# Load shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/config.sh"

check_required_tools jq curl

# ============================================
# Configuration
# ============================================

SESSION_DURATION="60"      # minutes (1-1440)
COUNTRY="dk"               # two-letter country code
# CITY="Hamburg"           # city name (underscores for spaces)
# STATE=""                 # US state code (us_state_name format)
# CONTINENT=""             # continent code (eu, na, as, sa, af, oc)
# ASN=""                   # ASN number

SESSION_PREFIX="session"
NUM_SESSIONS=3
CLEAN_THRESHOLD=50         # fraud score threshold for "clean" IPs

# ============================================
# Functions
# ============================================

build_auth_string() {
    local session_num=$1
    local auth="${DECODO_USERNAME}-sessionduration-${SESSION_DURATION}"
    
    # Location parameters (priority order)
    if [[ -n "${CONTINENT:-}" ]]; then
        auth+="-continent-${CONTINENT}"
    elif [[ -n "${COUNTRY:-}" ]]; then
        auth+="-country-${COUNTRY}"
        [[ -n "${STATE:-}" ]] && auth+="-state-${STATE}"
        [[ -n "${CITY:-}" && -z "${STATE:-}" ]] && auth+="-city-${CITY}"
    fi
    
    # ASN (cannot combine with city)
    [[ -n "${ASN:-}" && -z "${CITY:-}" ]] && auth+="-asn-${ASN}"
    
    echo "${auth}:${DECODO_PASSWORD}"
}

test_session() {
    local session_num=$1
    local result_file=$2
    local auth_string=$(build_auth_string "$session_num")
    local port=$(get_random_https_port)
    local proxy_url="https://${auth_string}@${PROXY_HOST_HTTPS}:${port}"
    local session_name="${SESSION_PREFIX}${session_num}"
    
    local response
    if response=$(curl -s --max-time 30 -x "${proxy_url}" "${DECODO_IP_API}" 2>/dev/null); then
        local ip=$(jq -r '.proxy.ip // empty' <<< "$response")
        local city=$(jq -r '.city.name // "Unknown"' <<< "$response")
        local country_code=$(jq -r '.country.code // "??"' <<< "$response")
        local country_name=$(jq -r '.country.name // "Unknown"' <<< "$response")
        
        if [[ -n "$ip" ]]; then
            echo "${session_name}|${ip}|${city}|${country_code}|${country_name}|${auth_string}|${port}" > "$result_file"
            return
        fi
    fi
    echo "FAIL|${session_name}|${port}" > "$result_file"
}

check_ip_fraud() {
    local ip=$1
    local result_file=$2
    local url="${IPQS_BASE_URL}/${IPQS_API_KEY}/${ip}"
    
    local response
    if response=$(curl -s --max-time 15 "$url" \
        --get \
        --data-urlencode "strictness=3" \
        --data-urlencode "user_agent=$USER_AGENT" \
        --data-urlencode "user_language=en-US" 2>/dev/null); then
        
        local success=$(jq -r '.success // false' <<< "$response")
        if [[ "$success" == "true" ]]; then
            local score=$(jq -r '.fraud_score // -1' <<< "$response")
            echo "${ip}|${score}" > "$result_file"
            return
        fi
    fi
    echo "${ip}|-1" > "$result_file"
}

print_summary() {
    local total=$1
    local unique=$2
    local clean=$3
    echo ""
    echo "Summary: $total sessions tested, $unique unique IPs, $clean clean IPs (score < $CLEAN_THRESHOLD)"
}

# ============================================
# Main
# ============================================

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

declare -a ip_list=()
declare -a city_list=()
declare -a country_list=()
declare -A proxy_links=()
declare -A session_to_ip=()
declare -A fraud_scores=()
declare -a clean_ips=()

# Print header
print_banner "Decodo SmartProxy HTTPS Checker"
echo "Host: $PROXY_HOST_HTTPS"
echo "Port range: $PROXY_PORT_HTTPS_MIN-$PROXY_PORT_HTTPS_MAX ($(( PROXY_PORT_HTTPS_MAX - PROXY_PORT_HTTPS_MIN + 1 )) rotating sessions)"

location=$(get_country_name "$COUNTRY")
[[ -n "${CITY:-}" ]] && location="$CITY, $location"
echo "Location: $location"
echo "Session duration: $SESSION_DURATION min | Sessions: $NUM_SESSIONS"
echo "======================================"

# Phase 1: Collect IPs
echo -e "\n[Phase 1] Testing proxy sessions..."

for i in $(seq 1 $NUM_SESSIONS); do
    test_session "$i" "${TEMP_DIR}/s${i}.result" &
done
wait

echo "Processing results..."

duplicates=0
failures=0

for i in $(seq 1 $NUM_SESSIONS); do
    result_file="${TEMP_DIR}/s${i}.result"
    [[ ! -f "$result_file" ]] && continue
    
    IFS='|' read -r f1 f2 f3 f4 f5 f6 f7 < "$result_file"
    
    if [[ "$f1" == "FAIL" ]]; then
        echo "✗ $f2 (port $f3)"
        ((failures++))
        continue
    fi
    
    session="$f1" ip="$f2" city="$f3" auth="$f6" port="$f7"
    
    # Check for duplicate IPs
    is_dup=false
    for existing in "${ip_list[@]}"; do
        [[ "$existing" == "$ip" ]] && { is_dup=true; ((duplicates++)); break; }
    done
    
    if $is_dup; then
        echo "⚡ $session: $ip (duplicate)"
    else
        echo "✓ $session: $ip ($city)"
        ip_list+=("$ip")
        city_list+=("$city")
        country_list+=("$f5")
        proxy_links["$ip"]="https://${auth}@${PROXY_HOST_HTTPS}:${port}"
        session_to_ip["$session"]="$ip"
    fi
done

echo -e "\nUnique IPs: ${#ip_list[@]} | Duplicates: $duplicates | Failures: $failures"

[[ ${#ip_list[@]} -eq 0 ]] && { echo "No IPs collected. Exiting."; exit 1; }

# Phase 2: Check fraud scores
echo -e "\n[Phase 2] Checking fraud scores..."

for ip in "${ip_list[@]}"; do
    check_ip_fraud "$ip" "${TEMP_DIR}/f_${ip}.result" &
    sleep 0.05  # Rate limiting
done
wait

echo "Processing fraud scores..."

for result_file in "${TEMP_DIR}"/f_*.result; do
    [[ ! -f "$result_file" ]] && continue
    
    IFS='|' read -r ip score < "$result_file"
    [[ "$score" == "-1" ]] && { echo "✗ $ip: API error"; continue; }
    
    fraud_scores["$ip"]=$score
    
    # Find city for this IP
    city="Unknown"
    for i in "${!ip_list[@]}"; do
        [[ "${ip_list[$i]}" == "$ip" ]] && { city="${city_list[$i]}"; break; }
    done
    
    # Find sessions for this IP
    sessions=""
    for s in "${!session_to_ip[@]}"; do
        [[ "${session_to_ip[$s]}" == "$ip" ]] && sessions+="${sessions:+, }$s"
    done
    
    emoji=$(get_score_emoji "$score")
    printf "%s %-15s Score: %3d  %-20s [%s]\n" "$emoji" "$ip" "$score" "$city" "$sessions"
    
    [[ "$score" -lt "$CLEAN_THRESHOLD" ]] && clean_ips+=("$ip")
done

# Phase 3: Results
echo ""
print_banner "Clean IPs (Score < $CLEAN_THRESHOLD)"

if [[ ${#clean_ips[@]} -gt 0 ]]; then
    # Sort by fraud score
    IFS=$'\n' sorted_ips=($(
        for ip in "${clean_ips[@]}"; do
            echo "${fraud_scores[$ip]} $ip"
        done | sort -n | awk '{print $2}'
    ))
    unset IFS
    
    for ip in "${sorted_ips[@]}"; do
        score=${fraud_scores[$ip]}
        
        # Find session and city
        session="" city=""
        for s in "${!session_to_ip[@]}"; do
            [[ "${session_to_ip[$s]}" == "$ip" ]] && { session=$s; break; }
        done
        for i in "${!ip_list[@]}"; do
            [[ "${ip_list[$i]}" == "$ip" ]] && { city="${city_list[$i]}"; break; }
        done
        
        emoji=$(get_score_emoji "$score")
        echo "$emoji Score: $score | $ip | $city | $session"
        echo "   ${proxy_links[$ip]}"
    done
    
    # Best proxy
    if [[ ${#sorted_ips[@]} -gt 0 ]]; then
        best_ip=${sorted_ips[0]}
        echo ""
        print_banner "Best Proxy (Score: ${fraud_scores[$best_ip]})"
        echo "${proxy_links[$best_ip]}"
    fi
else
    echo "No clean IPs found."
fi

print_summary "$NUM_SESSIONS" "${#ip_list[@]}" "${#clean_ips[@]}"
