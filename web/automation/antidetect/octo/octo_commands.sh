#!/bin/bash
# OctoBrowser Automation Commands

OCTO_PORT=$(cat ~/.Octo\ Browser/local_port 2>/dev/null || echo "51639")
OCTO_API="http://localhost:$OCTO_PORT"

# List active profiles
list_active() {
    curl -s "$OCTO_API/api/profiles/active" | python3 -m json.tool
}

# Start profile with debug port (for Playwright)
start_profile() {
    local uuid=$1
    curl -s -X POST "$OCTO_API/api/profiles/start" \
        -H "Content-Type: application/json" \
        -d "{\"uuid\": \"$uuid\", \"debug_port\": true}" | python3 -m json.tool
}

# Stop profile
stop_profile() {
    local uuid=$1
    curl -s -X POST "$OCTO_API/api/profiles/stop" \
        -H "Content-Type: application/json" \
        -d "{\"uuid\": \"$uuid\"}"
}

# Get profile details
get_profile() {
    local uuid=$1
    curl -s "$OCTO_API/api/v2/profiles/$uuid" | python3 -m json.tool
}

# Usage
echo "OctoBrowser API: $OCTO_API"
echo ""
echo "Commands:"
echo "  list_active              - List running profiles"
echo "  start_profile <uuid>     - Start profile with debug port"
echo "  stop_profile <uuid>      - Stop profile"
echo "  get_profile <uuid>       - Get profile details"
echo ""
echo "Example:"
echo "  source octo_commands.sh"
echo "  start_profile 51083d3a5c2b44dbb993ae6fa416e634"
