#!/usr/bin/env bash
# Production deploy helper for proxy-vpn.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }
timestamp() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

REPORT_FILE="${REPORT_FILE:-logs/deploy-history.log}"
RELEASE_STATE_FILE="${RELEASE_STATE_FILE:-logs/app-release-state.json}"
mkdir -p "$(dirname "${REPORT_FILE}")"
mkdir -p "$(dirname "${RELEASE_STATE_FILE}")"

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

release_info_for_head() {
  local short_sha
  short_sha="$(git rev-parse --short HEAD 2>/dev/null || echo na)"
  local content version notes
  content="$(git show "HEAD:RELEASE_NOTES.md" 2>/dev/null || true)"
  if [ -z "${content}" ]; then
    version="${short_sha}"
    notes="No release notes available."
  else
    version="$(printf '%s\n' "${content}" | awk '/^## /{sub(/^## /, "", $0); print; exit}')"
    [ -n "${version}" ] || version="${short_sha}"
    notes="$(
      printf '%s\n' "${content}" | awk '
      BEGIN { capture=0; out=""; n=0 }
      /^## / {
        if (capture==0) { capture=1; next }
        else { exit }
      }
      capture==1 {
        if (n < 8) {
          if (length(out) > 0) out = out " "
          out = out $0
          n++
        }
      }
      END { print out }'
    )"
    [ -n "${notes}" ] || notes="Release notes section is empty."
  fi
  printf '%s\n%s\n' "${version}" "${notes}"
}

write_release_state() {
  local update_status="${1:-updated}"
  local update_message="${2:-Deploy completed.}"
  local current_sha="${3:-na}"
  local current_version="${4:-na}"
  local current_notes="${5:-}"
  python3 - "$RELEASE_STATE_FILE" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path = sys.argv[1]
state = {
    "current": {
        "version": os.environ.get("REL_CURRENT_VERSION", "unknown"),
        "sha": os.environ.get("REL_CURRENT_SHA", "na"),
        "notes": os.environ.get("REL_CURRENT_NOTES", ""),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    },
    "available": None,
    "update": {
        "status": os.environ.get("REL_UPDATE_STATUS", "updated"),
        "message": os.environ.get("REL_UPDATE_MESSAGE", ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    },
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=True, indent=2)
    f.write("\n")
PY
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
  mapfile -t rb_info < <(release_info_for_head)
  REL_UPDATE_STATUS="failed_rollback_ok" \
  REL_UPDATE_MESSAGE="Deploy failed. Rolled back to previous healthy version ${rb_info[0]}." \
  REL_CURRENT_SHA="$(git rev-parse HEAD 2>/dev/null || echo na)" \
  REL_CURRENT_VERSION="${rb_info[0]}" \
  REL_CURRENT_NOTES="${rb_info[1]}" \
  write_release_state
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
mapfile -t rel_info < <(release_info_for_head)
REL_UPDATE_STATUS="updated" \
REL_UPDATE_MESSAGE="Application updated to version ${rel_info[0]}." \
REL_CURRENT_SHA="$(git rev-parse HEAD 2>/dev/null || echo na)" \
REL_CURRENT_VERSION="${rel_info[0]}" \
REL_CURRENT_NOTES="${rel_info[1]}" \
write_release_state
log "Next: verify domain HTTPS externally: https://${VPN_PANEL_DOMAIN}/health"
