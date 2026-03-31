#!/usr/bin/env bash
# Check API health via Caddy and print useful logs on failure.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

MODE="${MODE:-prod}" # prod or local
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found (need 'docker compose' or 'docker-compose')."
fi

# Load from .env when present, but allow runtime env-only checks.
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

wait_for_http() {
  local url=$1
  local max=${2:-90}
  local i=0
  while [ "${i}" -lt "${max}" ]; do
    if curl -sfS --connect-timeout 2 --max-time 5 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

compose_args=("-f" "compose.yaml")
if [ "${MODE}" = "prod" ]; then
  export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
  compose_args+=("-f" "compose.prod.yaml")
else
  export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-18080}"
fi

health_url="http://127.0.0.1:${CADDY_HTTP_PORT}/health"
log "--- health check via ${health_url} ---"
if wait_for_http "${health_url}" "${HEALTH_TIMEOUT}"; then
  log "OK: API reachable through Caddy"
  curl -sfS "${health_url}" || true
  echo
  exit 0
fi

log "FAIL: API not reachable through Caddy"
log "--- docker compose ps ---"
dc "${compose_args[@]}" ps || true
log "--- logs (caddy, api, xray, wireguard) ---"
dc "${compose_args[@]}" logs --tail 120 caddy api xray wireguard 2>&1 || true
exit 1
