#!/usr/bin/env bash
# Deprecated — use common/setup/init.sh <host>
exec bash "$(cd "$(dirname "$0")" && pwd)/init.sh" "$@"
