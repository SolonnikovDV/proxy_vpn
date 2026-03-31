#!/usr/bin/env bash
# Pull latest changes and rebuild/restart stack when branch changed.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s %s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')]" "$*"; }
die() { log "ERROR: $*"; exit 1; }
timestamp() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

REPORT_FILE="${REPORT_FILE:-logs/deploy-history.log}"
mkdir -p "$(dirname "${REPORT_FILE}")"

report_event() {
  local status="${1:-unknown}"
  local action="${2:-auto-update}"
  local details="${3:-}"
  local from_sha="${4:-na}"
  local to_sha="${5:-na}"
  local rollback_sha="${6:-na}"
  local clean_details
  clean_details="$(printf '%s' "${details}" | tr '\n' ' ' | tr '|' '/')"
  printf '%s|source=auto-update|status=%s|action=%s|branch=%s|from=%s|to=%s|rollback=%s|details=%s\n' \
    "$(timestamp)" "${status}" "${action}" "${BRANCH}" "${from_sha}" "${to_sha}" "${rollback_sha}" "${clean_details}" >> "${REPORT_FILE}"
}

BRANCH="${BRANCH:-main}"
MODE="${MODE:-prod}" # prod or local

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found"
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  die "Current directory is not a git repository"
fi

log "Fetching origin/${BRANCH}"
git fetch origin "${BRANCH}"

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"

if [ "${LOCAL_SHA}" = "${REMOTE_SHA}" ]; then
  log "No updates found, skip deploy"
  report_event "noop" "auto-update" "No updates found, skip deploy" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  exit 0
fi

if [ -n "$(git status --porcelain)" ]; then
  die "Working tree is dirty. Commit/stash local changes before auto-update."
fi

log "Applying updates: ${LOCAL_SHA} -> ${REMOTE_SHA}"
report_event "started" "auto-update" "Applying update and deploying new revision" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
git checkout "${BRANCH}"
git pull --ff-only origin "${BRANCH}"

deploy_current() {
  if [ "${MODE}" = "prod" ]; then
    [ -f .env ] || cp .env.prod.example .env
    log "Running production preflight"
    bash ./scripts/preflight-prod.sh
    log "Rebuilding/restarting production stack"
    dc -f compose.yaml -f compose.prod.yaml up -d --build
    dc -f compose.yaml -f compose.prod.yaml ps
    MODE=prod HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh
  else
    [ -f .env ] || cp .env.example .env
    log "Rebuilding/restarting local stack"
    dc -f compose.yaml up -d --build
    dc -f compose.yaml ps
    MODE=local HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh
  fi
}

rollback_to_previous() {
  log "Rolling back to previous commit: ${LOCAL_SHA}"
  git checkout -f "${LOCAL_SHA}"
  if [ "${MODE}" = "prod" ]; then
    dc -f compose.yaml -f compose.prod.yaml up -d --build
    MODE=prod HEALTH_TIMEOUT=120 bash ./scripts/healthcheck-stack.sh
  else
    dc -f compose.yaml up -d --build
    MODE=local HEALTH_TIMEOUT=120 bash ./scripts/healthcheck-stack.sh
  fi
}

if deploy_current; then
  log "Auto-update completed"
  report_event "success" "auto-update" "Update deployed and healthcheck passed" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  exit 0
fi

log "Updated revision failed health check."
report_event "failed" "auto-update" "Updated revision failed healthcheck" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
if rollback_to_previous; then
  report_event "failed_with_rollback" "auto-update" "Rollback to previous revision completed" "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_SHA}"
  die "Auto-update failed and rollback completed."
fi
report_event "failed_no_rollback" "auto-update" "Rollback to previous revision failed" "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_SHA}"
die "Auto-update failed and rollback failed."
