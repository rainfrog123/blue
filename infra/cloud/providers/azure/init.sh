#!/usr/bin/env bash
# Thin wrapper — shared bootstrap lives in common/setup/init.sh
exec bash "$(cd "$(dirname "$0")/../../common/setup" && pwd)/init.sh" azure "$@"
