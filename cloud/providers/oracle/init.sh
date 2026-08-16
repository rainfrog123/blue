#!/usr/bin/env bash
# Thin wrapper — shared bootstrap lives in common/setup/init.sh
# Usage: bash cloud/providers/oracle/init.sh [oracle-tokyo|oracle-tokyo2|oracle-a1]
# Live log: sudo tail -f /var/log/oracle-init.log
HOST="${1:-oracle-tokyo}"
shift || true
exec bash "$(cd "$(dirname "$0")/../../common/setup" && pwd)/init.sh" "$HOST" "$@"
