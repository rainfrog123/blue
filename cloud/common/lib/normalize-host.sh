# Host folders are kebab-case. Lowercase + underscores → hyphens.
# Usage: HOST="$(normalize_cloud_host "$HOST")"
normalize_cloud_host() {
  printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]' | tr '_' '-'
}
