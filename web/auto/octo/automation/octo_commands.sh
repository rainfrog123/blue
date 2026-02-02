#!/bin/bash
# OctoBrowser Local API — shell helpers
# See LOCAL_API.md for full reference.

OCTO_PORT=$(cat ~/.Octo\ Browser/local_port 2>/dev/null || echo "58888")
OCTO_BASE="http://localhost:$OCTO_PORT"

# List all profiles
octo_list() {
    curl -s -X POST "$OCTO_BASE/api/v2/profiles/list" \
        -H "Content-Type: application/json" \
        -d '{}' | python3 -m json.tool
}

# Create profile (quick): octo_create "My Profile" [win|mac|android|template]
octo_create() {
    local title="${1:-}"
    local os="${2:-win}"
    local body
    if [[ -n "$title" ]]; then
        body="{\"title\": \"$title\", \"os\": \"$os\"}"
    else
        body="{\"os\": \"$os\"}"
    fi
    curl -s -X POST "$OCTO_BASE/api/v2/profiles/quick" \
        -H "Content-Type: application/json" \
        -d "$body" | python3 -m json.tool
}

# Start profile: octo_start <uuid>
octo_start() {
    local uuid="$1"
    [[ -z "$uuid" ]] && { echo "Usage: octo_start <uuid>"; return 1; }
    curl -s -X POST "$OCTO_BASE/api/v2/profiles/$uuid/start" \
        -H "Content-Type: application/json" \
        -d '{}' | python3 -m json.tool
}

# Stop profile: octo_stop <uuid>
octo_stop() {
    local uuid="$1"
    [[ -z "$uuid" ]] && { echo "Usage: octo_stop <uuid>"; return 1; }
    curl -s -X POST "$OCTO_BASE/api/v2/profiles/$uuid/stop" \
        -H "Content-Type: application/json" \
        -d '{}' | python3 -m json.tool
}

# Get profile view: octo_view <uuid>
octo_view() {
    local uuid="$1"
    [[ -z "$uuid" ]] && { echo "Usage: octo_view <uuid>"; return 1; }
    curl -s "$OCTO_BASE/api/v2/profiles/$uuid/view" | python3 -m json.tool
}

# Check API is up
octo_ping() {
    curl -s "$OCTO_BASE/api/v2/client/themes" | python3 -m json.tool
}

# Usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "OctoBrowser API: $OCTO_BASE"
    echo ""
    echo "Source this file to use commands:"
    echo "  source octo_commands.sh"
    echo ""
    echo "Commands:"
    echo "  octo_ping              — Check API is up"
    echo "  octo_list               — List all profiles"
    echo "  octo_create [title] [os] — Create profile (os: win|mac|android|template)"
    echo "  octo_start <uuid>       — Start profile"
    echo "  octo_stop <uuid>        — Stop profile"
    echo "  octo_view <uuid>        — Get profile details"
    echo ""
    echo "Example:"
    echo "  source octo_commands.sh"
    echo "  octo_create \"Test Profile\" win"
    echo "  octo_start 61fe4cf012f446deb14443ca0d9d9ebb"
fi
