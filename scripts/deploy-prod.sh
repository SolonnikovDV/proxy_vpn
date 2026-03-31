#!/usr/bin/env bash
# Production deploy helper for proxy-vpn.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }
timestamp() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

REPORT_FILE="${REPORT_FILE:-logs/deploy-history.log}"
mkdir -p "$(dirname "${REPORT_FILE}")"

report_event() {
  local status="${1:-unknown}"
  local action="${2:-deploy}"
  local details="${3:-}"
  local from_sha="${4:-na}"
  local to_sha="${5:-na}"
  local rollback_sha="${6:-na}"
  local branch="${7:-na}"
  local clean_details
  clean_details="$(printf '%s' "${details}" | tr '\n' ' ' | tr '|' '/')"
  printf '%s|source=deploy-prod|status=%s|action=%s|branch=%s|from=%s|to=%s|rollback=%s|details=%s\n' \
    "$(timestamp)" "${status}" "${action}" "${branch}" "${from_sha}" "${to_sha}" "${rollback_sha}" "${clean_details}" >> "${REPORT_FILE}"
}

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found (need 'docker compose' or 'docker-compose')."
fi

log "--- preflight ---"
bash ./scripts/preflight-prod.sh

# Load from .env when present, but support runtime env-only deployment (CI/CD).
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
export CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
export XRAY_PORT="${XRAY_PORT:-8443}"
export WG_PORT="${WG_PORT:-51820}"

log "Deploying with:"
log "  domain=${VPN_PANEL_DOMAIN}"
log "  caddy_http=${CADDY_HTTP_PORT} caddy_https=${CADDY_HTTPS_PORT} xray=${XRAY_PORT} wg=${WG_PORT}"

prev_sha=""
fallback_sha=""
current_sha="na"
target_sha="na"
current_branch="na"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  current_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo na)"
  prev_sha="$(git rev-parse HEAD 2>/dev/null || true)"
  fallback_sha="$(git rev-parse HEAD~1 2>/dev/null || true)"
  current_sha="${prev_sha:-na}"
  target_sha="${current_sha}"
fi

rollback_to_prev() {
  local rollback_target="${fallback_sha:-$prev_sha}"
  [ -n "${rollback_target}" ] || return 1
  git cat-file -e "${rollback_target}^{commit}" >/dev/null 2>&1 || return 1
  log "--- rollback: checkout ${rollback_target} and redeploy ---"
  git checkout -f "${rollback_target}"
  dc -f compose.yaml -f compose.prod.yaml up -d --build
  MODE=prod HEALTH_TIMEOUT=120 bash ./scripts/healthcheck-stack.sh
  report_event "rollback_ok" "rollback" "Rollback deployment is healthy" "${current_sha}" "${target_sha}" "${rollback_target}" "${current_branch}"
}

report_event "started" "deploy" "Starting production deploy" "${current_sha}" "${target_sha}" "na" "${current_branch}"
dc -f compose.yaml -f compose.prod.yaml up -d --build

log "--- docker compose ps ---"
dc -f compose.yaml -f compose.prod.yaml ps

if ! MODE=prod HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh; then
  log "Primary deploy failed health check."
  report_event "failed" "deploy" "Primary deploy healthcheck failed" "${current_sha}" "${target_sha}" "na" "${current_branch}"
  if rollback_to_prev; then
    report_event "failed_with_rollback" "deploy" "Deploy failed, rollback completed" "${current_sha}" "${target_sha}" "${fallback_sha:-na}" "${current_branch}"
    die "Deploy failed and rollback to previous commit completed."
  fi
  report_event "failed_no_rollback" "deploy" "Deploy failed, rollback unavailable" "${current_sha}" "${target_sha}" "na" "${current_branch}"
  die "Deploy failed and rollback was not possible."
fi

log "Deploy completed."
report_event "success" "deploy" "Deploy completed and healthcheck passed" "${current_sha}" "${target_sha}" "na" "${current_branch}"
log "Next: verify domain HTTPS externally: https://${VPN_PANEL_DOMAIN}/health"
