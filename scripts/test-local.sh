#!/usr/bin/env bash
# Full-stack smoke test: requires Docker Desktop / Engine running on *your* machine.
# Cursor’s agent terminal often has no access to the host docker.sock — run this script locally in Terminal/iTerm.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }

is_port_free() {
  local port=$1
  # lsof is available on macOS by default.
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    return 1
  fi
  if lsof -nP -iUDP:"${port}" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

pick_port() {
  # Usage: pick_port 18080 28080 38080
  local port
  for port in "$@"; do
    if is_port_free "${port}"; then
      printf '%s\n' "${port}"
      return 0
    fi
  done
  return 1
}

# Compose v2 plugin ("docker compose", Docker Desktop 20.10+) or legacy docker-compose.
if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  log "Docker Compose not found. Install Compose v2 or docker-compose."
  exit 1
fi

wait_for_http() {
  local url=$1
  local name=$2
  local max=${3:-45}
  local i=0
  while [ "$i" -lt "$max" ]; do
    if curl -sfS --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
      log "OK: $name responded ($url)"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "FAIL: $name did not respond within ${max}s ($url)"
  return 1
}

assert_contains() {
  local haystack=$1
  local needle=$2
  local name=$3
  if printf '%s' "${haystack}" | grep -q "${needle}"; then
    log "OK: ${name}"
    return 0
  fi
  log "FAIL: ${name} (missing '${needle}')"
  return 1
}

if ! docker info >/dev/null 2>&1; then
  log "Docker is not running or not accessible."
  log "  • Start Docker Desktop (macOS) or the docker service (Linux)."
  log "  • If you use a remote engine, export DOCKER_HOST=..."
  exit 1
fi

bash ./scripts/sync-env.sh local

# Compose interpolates ${...}; shell env overrides .env.
# If user didn't set ports explicitly, pick a free one from a short fallback list.
export CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.dev}"
if [ -z "${CADDY_HTTP_PORT:-}" ]; then
  export CADDY_HTTP_PORT="$(pick_port 18080 28080 38080 8080 || true)"
fi
if [ -z "${CADDY_HTTPS_PORT:-}" ]; then
  export CADDY_HTTPS_PORT="$(pick_port 18443 28443 38443 8443 || true)"
fi
if [ -z "${XRAY_PORT:-}" ]; then
  export XRAY_PORT="$(pick_port 14443 24443 34443 8444 || true)"
fi

if [ -z "${CADDY_HTTP_PORT:-}" ] || [ -z "${CADDY_HTTPS_PORT:-}" ] || [ -z "${XRAY_PORT:-}" ]; then
  log "Failed to select free host ports automatically."
  log "Set explicit ports and retry, e.g.:"
  log "  CADDY_HTTP_PORT=18080 CADDY_HTTPS_PORT=18443 XRAY_PORT=14443 ./scripts/test-local.sh"
  exit 1
fi

log "Using Caddy config: ${CADDYFILE_PATH}"
log "Using ports: CADDY_HTTP_PORT=${CADDY_HTTP_PORT}, CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}, XRAY_PORT=${XRAY_PORT}"

log "--- docker compose build ---"
dc build

log "--- docker compose up -d ---"
dc up -d

log "--- docker compose ps ---"
dc ps -a

log "--- wait for API via Caddy (HTTP :${CADDY_HTTP_PORT}) ---"
if ! wait_for_http "http://127.0.0.1:${CADDY_HTTP_PORT}/health" "Caddy->API /health" 45; then
  log "--- tail logs (api, caddy) ---"
  dc logs --tail 80 api caddy 2>&1 || true
  exit 1
fi

log "--- curl Caddy -> API (HTTP) ---"
health_body="$(curl -sfS "http://127.0.0.1:${CADDY_HTTP_PORT}/health")"
printf '%s\n' "${health_body}"
echo
meta_body="$(curl -sfS "http://127.0.0.1:${CADDY_HTTP_PORT}/api/v1/meta")"
printf '%s\n' "${meta_body}"
echo
assert_contains "${health_body}" "\"status\":\"ok\"" "HTTP /health is proxied to API"
assert_contains "${meta_body}" "\"service\":\"proxy-vpn\"" "HTTP /api/v1/meta is proxied to API"

log "--- HTTPS panel (self-signed): https://localhost:${CADDY_HTTPS_PORT}/health ---"
https_body="$(curl -skSfS --connect-timeout 2 --max-time 5 "https://localhost:${CADDY_HTTPS_PORT}/health" || true)"
if [ -n "${https_body}" ]; then
  printf '%s\n' "${https_body}" | head -c 200
  echo
  assert_contains "${https_body}" "\"status\":\"ok\"" "HTTPS /health is proxied to API"
else
  log "(HTTPS check skipped or failed — OK if browser trust is required)"
fi

log "Xray demo inbound on host TCP port ${XRAY_PORT} (container listens on 443)."
dc ps xray 2>/dev/null || true

log "WireGuard: without wireguard/conf/wg0.conf the wg container waits — OK for API/Caddy/Xray smoke test."
log "Follow logs: docker compose logs -f caddy api xray wireguard"
log "Tip (macOS): if \`docker info\` fails in some tools, try: export DOCKER_HOST=unix://\${HOME}/.docker/run/docker.sock"
