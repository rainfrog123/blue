#!/usr/bin/env bash
# Thin wrapper — shared bootstrap lives in common/setup/init.sh
# Pass digi|ali|azure when known; otherwise auto-detect from DMI.
if [[ $# -gt 0 ]]; then
  exec bash "$(cd "$(dirname "$0")/../../common/setup" && pwd)/init.sh" "$@"
else
  exec bash "$(cd "$(dirname "$0")/../../common/setup" && pwd)/init.sh"
fi
