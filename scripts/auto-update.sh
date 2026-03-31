#!/usr/bin/env bash
# Pull latest changes and rebuild/restart stack when branch changed.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s %s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')]" "$*"; }
die() { log "ERROR: $*"; exit 1; }
timestamp() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

REPORT_FILE="${REPORT_FILE:-logs/deploy-history.log}"
RELEASE_STATE_FILE="${RELEASE_STATE_FILE:-logs/app-release-state.json}"
UPDATE_CHECK_REQUEST_FILE="${UPDATE_CHECK_REQUEST_FILE:-logs/update-check-request.json}"
UPDATE_APPLY_REQUEST_FILE="${UPDATE_APPLY_REQUEST_FILE:-logs/update-apply-request.json}"
UPDATE_APPROVAL_REQUIRED="${UPDATE_APPROVAL_REQUIRED:-1}"
mkdir -p "$(dirname "${REPORT_FILE}")"
mkdir -p "$(dirname "${RELEASE_STATE_FILE}")"

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

release_info_for_ref() {
  local ref="$1"
  local fallback_sha="${2:-na}"
  local content
  content="$(git show "${ref}:RELEASE_NOTES.md" 2>/dev/null || true)"
  local version notes
  if [ -z "${content}" ]; then
    version="${fallback_sha}"
    notes="No release notes available."
  else
    version="$(printf '%s\n' "${content}" | awk '/^## /{sub(/^## /, "", $0); print; exit}')"
    if [ -z "${version}" ]; then
      version="${fallback_sha}"
    fi
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
    if [ -z "${notes}" ]; then
      notes="Release notes section is empty."
    fi
  fi
  printf '%s\n%s\n' "${version}" "${notes}"
}

write_release_state() {
  local update_status="${1:-idle}"
  local update_message="${2:-}"
  local current_sha="${3:-na}"
  local current_version="${4:-na}"
  local current_notes="${5:-}"
  local available_sha="${6:-}"
  local available_version="${7:-}"
  local available_notes="${8:-}"
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
        "status": os.environ.get("REL_UPDATE_STATUS", "idle"),
        "message": os.environ.get("REL_UPDATE_MESSAGE", ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    },
}
av_sha = os.environ.get("REL_AVAILABLE_SHA", "").strip()
if av_sha:
    state["available"] = {
        "version": os.environ.get("REL_AVAILABLE_VERSION", "unknown"),
        "sha": av_sha,
        "notes": os.environ.get("REL_AVAILABLE_NOTES", ""),
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
with open(path, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=True, indent=2)
    f.write("\n")
PY
}

log "Fetching origin/${BRANCH}"
git fetch origin "${BRANCH}"

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"
LOCAL_SHORT="$(git rev-parse --short HEAD)"
REMOTE_SHORT="$(git rev-parse --short "origin/${BRANCH}")"
mapfile -t local_info < <(release_info_for_ref "HEAD" "${LOCAL_SHORT}")
LOCAL_VERSION="${local_info[0]:-${LOCAL_SHORT}}"
LOCAL_NOTES="${local_info[1]:-No release notes available.}"

if [ "${LOCAL_SHA}" != "${REMOTE_SHA}" ]; then
  mapfile -t remote_info < <(release_info_for_ref "origin/${BRANCH}" "${REMOTE_SHORT}")
  REMOTE_VERSION="${remote_info[0]:-${REMOTE_SHORT}}"
  REMOTE_NOTES="${remote_info[1]:-No release notes available.}"
else
  REMOTE_VERSION=""
  REMOTE_NOTES=""
fi

check_requested="0"
[ -f "${UPDATE_CHECK_REQUEST_FILE}" ] && check_requested="1"
apply_requested="0"
[ -f "${UPDATE_APPLY_REQUEST_FILE}" ] && apply_requested="1"

if [ "${LOCAL_SHA}" = "${REMOTE_SHA}" ]; then
  log "No updates found, skip deploy"
  report_event "noop" "auto-update" "No updates found, skip deploy" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  REL_UPDATE_STATUS="up_to_date" \
  REL_UPDATE_MESSAGE="No updates available." \
  REL_CURRENT_SHA="${LOCAL_SHA}" \
  REL_CURRENT_VERSION="${LOCAL_VERSION}" \
  REL_CURRENT_NOTES="${LOCAL_NOTES}" \
  REL_AVAILABLE_SHA="" \
  REL_AVAILABLE_VERSION="" \
  REL_AVAILABLE_NOTES="" \
  write_release_state
  rm -f "${UPDATE_CHECK_REQUEST_FILE}" "${UPDATE_APPLY_REQUEST_FILE}"
  exit 0
fi

if [ -n "$(git status --porcelain)" ]; then
  die "Working tree is dirty. Commit/stash local changes before auto-update."
fi

if [ "${UPDATE_APPROVAL_REQUIRED}" = "1" ] && [ "${apply_requested}" != "1" ]; then
  log "Update is available but waits for manual apply request."
  report_event "awaiting_approval" "auto-update" "Update available, waiting for admin apply request" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  REL_UPDATE_STATUS="available" \
  REL_UPDATE_MESSAGE="Update available. Press Update in application to apply." \
  REL_CURRENT_SHA="${LOCAL_SHA}" \
  REL_CURRENT_VERSION="${LOCAL_VERSION}" \
  REL_CURRENT_NOTES="${LOCAL_NOTES}" \
  REL_AVAILABLE_SHA="${REMOTE_SHA}" \
  REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
  REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
  write_release_state
  rm -f "${UPDATE_CHECK_REQUEST_FILE}"
  exit 0
fi

log "Applying updates: ${LOCAL_SHA} -> ${REMOTE_SHA}"
report_event "started" "auto-update" "Applying update and deploying new revision" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
REL_UPDATE_STATUS="updating" \
REL_UPDATE_MESSAGE="Applying update and rebuilding services." \
REL_CURRENT_SHA="${LOCAL_SHA}" \
REL_CURRENT_VERSION="${LOCAL_VERSION}" \
REL_CURRENT_NOTES="${LOCAL_NOTES}" \
REL_AVAILABLE_SHA="${REMOTE_SHA}" \
REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
write_release_state
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
  mapfile -t new_info < <(release_info_for_ref "HEAD" "$(git rev-parse --short HEAD)")
  NEW_VERSION="${new_info[0]:-$(git rev-parse --short HEAD)}"
  NEW_NOTES="${new_info[1]:-No release notes available.}"
  REL_UPDATE_STATUS="updated" \
  REL_UPDATE_MESSAGE="Application updated to version ${NEW_VERSION}." \
  REL_CURRENT_SHA="$(git rev-parse HEAD)" \
  REL_CURRENT_VERSION="${NEW_VERSION}" \
  REL_CURRENT_NOTES="${NEW_NOTES}" \
  REL_AVAILABLE_SHA="" \
  REL_AVAILABLE_VERSION="" \
  REL_AVAILABLE_NOTES="" \
  write_release_state
  rm -f "${UPDATE_CHECK_REQUEST_FILE}" "${UPDATE_APPLY_REQUEST_FILE}"
  exit 0
fi

log "Updated revision failed health check."
report_event "failed" "auto-update" "Updated revision failed healthcheck" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
if rollback_to_previous; then
  report_event "failed_with_rollback" "auto-update" "Rollback to previous revision completed" "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_SHA}"
  mapfile -t rb_info < <(release_info_for_ref "HEAD" "$(git rev-parse --short HEAD)")
  RB_VERSION="${rb_info[0]:-$(git rev-parse --short HEAD)}"
  RB_NOTES="${rb_info[1]:-No release notes available.}"
  REL_UPDATE_STATUS="failed_rollback_ok" \
  REL_UPDATE_MESSAGE="Update failed. Rolled back to previous healthy version ${RB_VERSION}." \
  REL_CURRENT_SHA="$(git rev-parse HEAD)" \
  REL_CURRENT_VERSION="${RB_VERSION}" \
  REL_CURRENT_NOTES="${RB_NOTES}" \
  REL_AVAILABLE_SHA="${REMOTE_SHA}" \
  REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
  REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
  write_release_state
  rm -f "${UPDATE_CHECK_REQUEST_FILE}" "${UPDATE_APPLY_REQUEST_FILE}"
  die "Auto-update failed and rollback completed."
fi
report_event "failed_no_rollback" "auto-update" "Rollback to previous revision failed" "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_SHA}"
REL_UPDATE_STATUS="failed" \
REL_UPDATE_MESSAGE="Update failed and rollback failed. Manual recovery required." \
REL_CURRENT_SHA="${LOCAL_SHA}" \
REL_CURRENT_VERSION="${LOCAL_VERSION}" \
REL_CURRENT_NOTES="${LOCAL_NOTES}" \
REL_AVAILABLE_SHA="${REMOTE_SHA}" \
REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
write_release_state
rm -f "${UPDATE_CHECK_REQUEST_FILE}" "${UPDATE_APPLY_REQUEST_FILE}"
die "Auto-update failed and rollback failed."
