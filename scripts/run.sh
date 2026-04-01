#!/usr/bin/env bash
# Unified launcher for local/prod docker compose modes.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  bash ./scripts/run.sh local [up|down|restart|logs|ps]
  bash ./scripts/run.sh prod  [up|down|restart|logs|ps]

Examples:
  bash ./scripts/run.sh local up
  bash ./scripts/run.sh local logs
  bash ./scripts/run.sh prod up
  bash ./scripts/run.sh prod down
EOF
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

MODE="${1:-}"
ACTION="${2:-up}"

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found (need 'docker compose' or 'docker-compose')."
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running or not accessible."
fi

run_local() {
  bash ./scripts/sync-env.sh local
  export CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.dev}"
  export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-18080}"
  export CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-18443}"
  export XRAY_PORT="${XRAY_PORT:-14443}"

  case "${ACTION}" in
    up)
      dc -f compose.yaml up -d --build
      dc -f compose.yaml ps
      log "Local URLs:"
      log "  http://127.0.0.1:${CADDY_HTTP_PORT}/"
      log "  http://127.0.0.1:${CADDY_HTTP_PORT}/login"
      ;;
    down)
      dc -f compose.yaml down
      ;;
    restart)
      dc -f compose.yaml down
      dc -f compose.yaml up -d --build
      dc -f compose.yaml ps
      ;;
    logs)
      dc -f compose.yaml logs -f caddy api xray wireguard
      ;;
    ps)
      dc -f compose.yaml ps
      ;;
    *)
      die "Unknown action: ${ACTION}"
      ;;
  esac
}

run_prod() {
  bash ./scripts/sync-env.sh prod
  set -a
  . ./.env
  set +a
  export VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-}"
  export XRAY_PORT="${XRAY_PORT:-8443}"
  export WG_PORT="${WG_PORT:-51820}"
  case "${ACTION}" in
    up)
      bash ./scripts/preflight-prod.sh
      dc -f compose.yaml -f compose.prod.yaml up -d --build
      dc -f compose.yaml -f compose.prod.yaml ps
      log "Production URLs:"
      log "  https://${VPN_PANEL_DOMAIN}/"
      log "  https://${VPN_PANEL_DOMAIN}/login"
      log "  https://${VPN_PANEL_DOMAIN}/admin"
      log "VPN endpoints:"
      log "  WireGuard endpoint: ${VPN_PANEL_DOMAIN}:${WG_PORT} (client: wireguard/conf/client1.conf)"
      log "  Xray endpoint: ${VPN_PANEL_DOMAIN}:${XRAY_PORT} (client: xray/client-connection.txt)"
      ;;
    down)
      dc -f compose.yaml -f compose.prod.yaml down
      ;;
    restart)
      dc -f compose.yaml -f compose.prod.yaml down
      bash ./scripts/preflight-prod.sh
      dc -f compose.yaml -f compose.prod.yaml up -d --build
      dc -f compose.yaml -f compose.prod.yaml ps
      log "Production URLs:"
      log "  https://${VPN_PANEL_DOMAIN}/"
      log "  https://${VPN_PANEL_DOMAIN}/login"
      log "  https://${VPN_PANEL_DOMAIN}/admin"
      log "VPN endpoints:"
      log "  WireGuard endpoint: ${VPN_PANEL_DOMAIN}:${WG_PORT} (client: wireguard/conf/client1.conf)"
      log "  Xray endpoint: ${VPN_PANEL_DOMAIN}:${XRAY_PORT} (client: xray/client-connection.txt)"
      ;;
    logs)
      dc -f compose.yaml -f compose.prod.yaml logs -f caddy api xray wireguard
      ;;
    ps)
      dc -f compose.yaml -f compose.prod.yaml ps
      ;;
    *)
      die "Unknown action: ${ACTION}"
      ;;
  esac
}

case "${MODE}" in
  local)
    run_local
    ;;
  prod)
    run_prod
    ;;
  *)
    die "Unknown mode: ${MODE}. Use 'local' or 'prod'."
    ;;
esac
