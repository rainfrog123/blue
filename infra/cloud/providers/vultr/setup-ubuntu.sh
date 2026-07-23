#!/usr/bin/env bash
# Deprecated name — use init.sh
exec bash "$(cd "$(dirname "$0")" && pwd)/init.sh" "$@"
