#!/usr/bin/env bash
# Deprecated path — universal bootstrap is common/setup/init.sh
# Usage: bash infra/cloud/common/lib/os.sh digi|ali|azure
exec bash "$(cd "$(dirname "$0")/../setup" && pwd)/init.sh" "$@"
