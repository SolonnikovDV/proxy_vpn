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

check_prod_route_not_fallback() {
  local route="$1"
  local url="https://${VPN_PANEL_DOMAIN}${route}"
  local tmp_file=""
  local code=""
  local code_num=0
  local body=""
  local attempt=1
  while [ "${attempt}" -le 10 ]; do
    tmp_file="$(mktemp)"
    code="$(curl -ksS --max-time 10 -o "${tmp_file}" -w "%{http_code}" "${url}" || true)"
    body="$(tr -d '\r' < "${tmp_file}" || true)"
    rm -f "${tmp_file}" || true
    if [[ "${code}" =~ ^[0-9]{3}$ ]]; then
      code_num=$((10#${code}))
    else
      code_num=0
    fi
    if [ "${code_num}" -ge 200 ] && [ "${code_num}" -lt 500 ] && [[ "${body}" != *"proxy-vpn panel"* ]]; then
      log "Smoke route OK: ${route} (HTTP ${code})"
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  die "Smoke route failed for ${route}: fallback/invalid response at ${url}"
}

run_prod_smoke_checks() {
  log "Running production route smoke checks..."
  check_prod_route_not_fallback "/about"
  check_prod_route_not_fallback "/about/"
  check_prod_route_not_fallback "/admin"
}

run_prod() {
  bash ./scripts/sync-env.sh prod
  set -a
  . ./.env
  set +a
  export CADDYFILE_PATH="Caddyfile.prod"
  export VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-}"
  export XRAY_PORT="${XRAY_PORT:-8443}"
  export WG_PORT="${WG_PORT:-51820}"
  export XRAY_CLIENT_PORT="${XRAY_CLIENT_PORT:-${XRAY_PORT}}"
  export WG_CLIENT_PORT="${WG_CLIENT_PORT:-${WG_PORT}}"
  export PRESERVE_VPN_CORE_ON_REBUILD="${PRESERVE_VPN_CORE_ON_REBUILD:-1}"
  export VPN_CORE_REBUILD_MODE="${VPN_CORE_REBUILD_MODE:-auto}" # auto | always | never
  export PROD_DEPLOY_SHA_FILE="${PROD_DEPLOY_SHA_FILE:-logs/last-prod-up.sha}"
  mkdir -p "$(dirname "${PROD_DEPLOY_SHA_FILE}")"
  vpn_core_rebuild_required_for_range() {
    local from_ref="$1"
    local to_ref="$2"
    local changed
    changed="$(git diff --name-only "${from_ref}..${to_ref}" 2>/dev/null || true)"
    [ -z "${changed}" ] && return 1
    while IFS= read -r path; do
      [ -z "${path}" ] && continue
      case "${path}" in
        xray/*|wireguard/*|compose.yaml|compose.prod.yaml|Caddyfile.prod|Caddyfile.dev|scripts/setup-xray-reality.sh|scripts/setup-wireguard.sh|scripts/preflight-prod.sh)
          return 0
          ;;
      esac
    done <<EOF
${changed}
EOF
    return 1
  }
  detect_vpn_core_rebuild_flag() {
    case "${VPN_CORE_REBUILD_MODE}" in
      always)
        printf '1'
        return 0
        ;;
      never)
        printf '0'
        return 0
        ;;
      auto) ;;
      *)
        die "Unknown VPN_CORE_REBUILD_MODE=${VPN_CORE_REBUILD_MODE}. Use auto|always|never."
        ;;
    esac
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf '0'
      return 0
    fi
    local current_sha previous_sha
    current_sha="$(git rev-parse HEAD 2>/dev/null || true)"
    previous_sha="$( [ -f "${PROD_DEPLOY_SHA_FILE}" ] && tr -d '\r\n' < "${PROD_DEPLOY_SHA_FILE}" || true )"
    if [ -z "${previous_sha}" ] || [ -z "${current_sha}" ] || [ "${previous_sha}" = "${current_sha}" ]; then
      printf '0'
      return 0
    fi
    if vpn_core_rebuild_required_for_range "${previous_sha}" "${current_sha}"; then
      printf '1'
    else
      printf '0'
    fi
  }
  ensure_vpn_core_running() {
    # Do not recreate xray/wireguard in safe mode; only start them if stopped.
    if ! dc -f compose.yaml -f compose.prod.yaml start xray wireguard >/dev/null 2>&1; then
      dc -f compose.yaml -f compose.prod.yaml up -d xray wireguard
    fi
  }
  prod_up_stack() {
    local vpn_core_rebuild
    vpn_core_rebuild="$(detect_vpn_core_rebuild_flag)"
    if [ "${PRESERVE_VPN_CORE_ON_REBUILD}" = "1" ] && [ "${vpn_core_rebuild}" != "1" ]; then
      log "Safe mode: no VPN core changes detected; preserving active VPN tunnels."
      dc -f compose.yaml -f compose.prod.yaml up -d --build api security-guard caddy
      ensure_vpn_core_running
    elif [ "${PRESERVE_VPN_CORE_ON_REBUILD}" = "1" ] && [ "${vpn_core_rebuild}" = "1" ]; then
      log "VPN core changes detected; rebuilding full stack (including xray/wireguard)."
      dc -f compose.yaml -f compose.prod.yaml up -d --build
    else
      log "Full rebuild mode: rebuilding all services including VPN core."
      dc -f compose.yaml -f compose.prod.yaml up -d --build
    fi
  }
  mark_prod_deploy_sha() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git rev-parse HEAD > "${PROD_DEPLOY_SHA_FILE}" 2>/dev/null || true
    fi
  }
  apply_dynamic_port_map() {
    if [ -x "./scripts/apply-port-map.sh" ]; then
      XRAY_PORT="${XRAY_PORT}" \
      WG_PORT="${WG_PORT}" \
      XRAY_CLIENT_PORT="${XRAY_CLIENT_PORT}" \
      WG_CLIENT_PORT="${WG_CLIENT_PORT}" \
      CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}" \
      bash ./scripts/apply-port-map.sh
    fi
  }
  case "${ACTION}" in
    up)
      bash ./scripts/preflight-prod.sh
      prod_up_stack
      apply_dynamic_port_map
      dc -f compose.yaml -f compose.prod.yaml up -d --force-recreate caddy
      run_prod_smoke_checks
      dc -f compose.yaml -f compose.prod.yaml ps
      mark_prod_deploy_sha
      log "Production URLs:"
      log "  https://${VPN_PANEL_DOMAIN}/"
      log "  https://${VPN_PANEL_DOMAIN}/login"
      log "  https://${VPN_PANEL_DOMAIN}/admin"
      log "VPN endpoints:"
      log "  WireGuard runtime: ${VPN_PANEL_DOMAIN}:${WG_PORT} | client: ${VPN_PANEL_DOMAIN}:${WG_CLIENT_PORT}"
      log "  Xray runtime: ${VPN_PANEL_DOMAIN}:${XRAY_PORT} | client: ${VPN_PANEL_DOMAIN}:${XRAY_CLIENT_PORT}"
      ;;
    down)
      dc -f compose.yaml -f compose.prod.yaml down
      ;;
    restart)
      if [ "${PRESERVE_VPN_CORE_ON_REBUILD}" != "1" ]; then
        dc -f compose.yaml -f compose.prod.yaml down
      fi
      bash ./scripts/preflight-prod.sh
      prod_up_stack
      apply_dynamic_port_map
      dc -f compose.yaml -f compose.prod.yaml up -d --force-recreate caddy
      run_prod_smoke_checks
      dc -f compose.yaml -f compose.prod.yaml ps
      mark_prod_deploy_sha
      log "Production URLs:"
      log "  https://${VPN_PANEL_DOMAIN}/"
      log "  https://${VPN_PANEL_DOMAIN}/login"
      log "  https://${VPN_PANEL_DOMAIN}/admin"
      log "VPN endpoints:"
      log "  WireGuard runtime: ${VPN_PANEL_DOMAIN}:${WG_PORT} | client: ${VPN_PANEL_DOMAIN}:${WG_CLIENT_PORT}"
      log "  Xray runtime: ${VPN_PANEL_DOMAIN}:${XRAY_PORT} | client: ${VPN_PANEL_DOMAIN}:${XRAY_CLIENT_PORT}"
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
