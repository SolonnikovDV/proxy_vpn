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
UPDATE_AUDIT_FILE="${UPDATE_AUDIT_FILE:-logs/update-audit.jsonl}"
UPDATE_APPROVAL_REQUIRED="${UPDATE_APPROVAL_REQUIRED:-0}"
LOCAL_CHANGES_POLICY="${LOCAL_CHANGES_POLICY:-stash}" # stash | commit | fail
LOCAL_CHANGES_COMMIT_MESSAGE="${LOCAL_CHANGES_COMMIT_MESSAGE:-chore(auto-update): checkpoint local changes before pull}"
REPO_SYNC_STRATEGY="${REPO_SYNC_STRATEGY:-mirror}" # mirror | pull
REQUIRE_GREEN_CI="${REQUIRE_GREEN_CI:-1}"
GITHUB_REPO="${GITHUB_REPO:-}"
GITHUB_API_TOKEN="${GITHUB_API_TOKEN:-${GH_TOKEN:-${GITHUB_TOKEN:-}}}"
mkdir -p "$(dirname "${REPORT_FILE}")"
mkdir -p "$(dirname "${RELEASE_STATE_FILE}")"
mkdir -p "$(dirname "${UPDATE_AUDIT_FILE}")"

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

append_update_audit() {
  local status="$1"
  local message="$2"
  local from_sha="$3"
  local to_sha="$4"
  local local_change_result="${5:-none}"
  local commits_file files_file
  commits_file="$(mktemp)"
  files_file="$(mktemp)"
  if [ -n "${from_sha}" ] && [ -n "${to_sha}" ] && [ "${from_sha}" != "${to_sha}" ]; then
    git log --pretty=format:'%H%x09%s' "${from_sha}..${to_sha}" > "${commits_file}" || true
    git diff --name-status "${from_sha}..${to_sha}" > "${files_file}" || true
  fi
  python3 - "${UPDATE_AUDIT_FILE}" "${status}" "${message}" "${BRANCH}" "${from_sha}" "${to_sha}" "${local_change_result}" "${commits_file}" "${files_file}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

out_path = Path(sys.argv[1])
status = sys.argv[2]
message = sys.argv[3]
branch = sys.argv[4]
from_sha = sys.argv[5]
to_sha = sys.argv[6]
local_change_result = sys.argv[7]
commits_path = Path(sys.argv[8])
files_path = Path(sys.argv[9])

commits = []
if commits_path.exists():
    for raw in commits_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        if "\t" in raw:
            sha, title = raw.split("\t", 1)
        else:
            sha, title = raw.strip(), ""
        commits.append({"sha": sha.strip(), "title": title.strip()})

files = []
if files_path.exists():
    for raw in files_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t", 1)
        if len(parts) == 2:
            files.append({"status": parts[0].strip(), "path": parts[1].strip()})

entry = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "source": "auto-update",
    "status": status,
    "branch": branch,
    "from": from_sha,
    "to": to_sha,
    "message": message,
    "local_changes": local_change_result,
    "commit_count": len(commits),
    "file_count": len(files),
    "commits": commits,
    "files": files,
}

out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("a", encoding="utf-8") as f:
    f.write(json.dumps(entry, ensure_ascii=True) + "\n")
PY
  rm -f "${commits_file}" "${files_file}" >/dev/null 2>&1 || true
}

BRANCH="${BRANCH:-main}"
MODE="${MODE:-prod}" # prod or local

case "${REPO_SYNC_STRATEGY}" in
  mirror|pull) ;;
  *) die "Unknown REPO_SYNC_STRATEGY=${REPO_SYNC_STRATEGY}. Use mirror|pull." ;;
esac

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

infer_github_repo_from_origin() {
  local origin_url
  origin_url="$(git remote get-url origin 2>/dev/null || true)"
  if [ -z "${origin_url}" ]; then
    return 1
  fi
  if [[ "${origin_url}" == git@github.com:* ]]; then
    printf '%s' "${origin_url#git@github.com:}" | sed -E 's#\.git$##'
    return 0
  fi
  if [[ "${origin_url}" == https://github.com/* ]]; then
    printf '%s' "${origin_url#https://github.com/}" | sed -E 's#\.git$##'
    return 0
  fi
  return 1
}

github_commit_status_state() {
  local repo="$1"
  local sha="$2"
  local token="$3"
  python3 - "$repo" "$sha" "$token" <<'PY'
import json
import sys
import urllib.request

repo = sys.argv[1]
sha = sys.argv[2]
token = sys.argv[3].strip()
url = f"https://api.github.com/repos/{repo}/commits/{sha}/status"
req = urllib.request.Request(url, headers={
    "Accept": "application/vnd.github+json",
    "User-Agent": "proxy-vpn-auto-update",
})
if token:
    req.add_header("Authorization", f"Bearer {token}")
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
except Exception as e:
    print(f"__ERROR__:{e}")
    raise SystemExit(0)
state = str(payload.get("state", "")).strip().lower()
if not state:
    print("__ERROR__:empty_state")
    raise SystemExit(0)
print(state)
PY
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

if [ "${REQUIRE_GREEN_CI}" = "1" ]; then
  repo_for_ci="${GITHUB_REPO}"
  if [ -z "${repo_for_ci}" ]; then
    repo_for_ci="$(infer_github_repo_from_origin || true)"
  fi
  if [ -z "${repo_for_ci}" ]; then
    report_event "blocked_ci_gate" "auto-update" "Cannot infer GitHub repo for CI gate check; update skipped" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
    append_update_audit "blocked_ci_gate" "Cannot infer GitHub repo for CI gate check; update skipped." "${LOCAL_SHA}" "${REMOTE_SHA}" "none"
    REL_UPDATE_STATUS="available" \
    REL_UPDATE_MESSAGE="Update available, but CI gate check is not configured (missing GITHUB_REPO)." \
    REL_CURRENT_SHA="${LOCAL_SHA}" \
    REL_CURRENT_VERSION="${LOCAL_VERSION}" \
    REL_CURRENT_NOTES="${LOCAL_NOTES}" \
    REL_AVAILABLE_SHA="${REMOTE_SHA}" \
    REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
    REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
    write_release_state
    exit 0
  fi
  ci_state="$(github_commit_status_state "${repo_for_ci}" "${REMOTE_SHA}" "${GITHUB_API_TOKEN}")"
  if [[ "${ci_state}" == __ERROR__:* ]]; then
    report_event "blocked_ci_gate" "auto-update" "CI gate check error: ${ci_state#__ERROR__:}" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
    append_update_audit "blocked_ci_gate" "CI gate check error; update skipped." "${LOCAL_SHA}" "${REMOTE_SHA}" "none"
    REL_UPDATE_STATUS="available" \
    REL_UPDATE_MESSAGE="Update available, but CI gate check failed (${ci_state#__ERROR__:})." \
    REL_CURRENT_SHA="${LOCAL_SHA}" \
    REL_CURRENT_VERSION="${LOCAL_VERSION}" \
    REL_CURRENT_NOTES="${LOCAL_NOTES}" \
    REL_AVAILABLE_SHA="${REMOTE_SHA}" \
    REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
    REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
    write_release_state
    exit 0
  fi
  if [ "${ci_state}" != "success" ]; then
    report_event "awaiting_ci_green" "auto-update" "Update skipped until CI is green (state=${ci_state})" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
    append_update_audit "awaiting_ci_green" "Update available, waiting for green CI." "${LOCAL_SHA}" "${REMOTE_SHA}" "none"
    REL_UPDATE_STATUS="available" \
    REL_UPDATE_MESSAGE="Update available, waiting for green CI (state=${ci_state})." \
    REL_CURRENT_SHA="${LOCAL_SHA}" \
    REL_CURRENT_VERSION="${LOCAL_VERSION}" \
    REL_CURRENT_NOTES="${LOCAL_NOTES}" \
    REL_AVAILABLE_SHA="${REMOTE_SHA}" \
    REL_AVAILABLE_VERSION="${REMOTE_VERSION}" \
    REL_AVAILABLE_NOTES="${REMOTE_NOTES}" \
    write_release_state
    exit 0
  fi
fi

check_requested="0"
[ -f "${UPDATE_CHECK_REQUEST_FILE}" ] && check_requested="1"
apply_requested="0"
[ -f "${UPDATE_APPLY_REQUEST_FILE}" ] && apply_requested="1"

if [ "${LOCAL_SHA}" = "${REMOTE_SHA}" ]; then
  log "No updates found, skip deploy"
  report_event "noop" "auto-update" "No updates found, skip deploy" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  append_update_audit "noop" "No updates available." "${LOCAL_SHA}" "${REMOTE_SHA}" "none"
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

LOCAL_CHANGE_RESULT="none"
PULL_MODE="ff-only"
if [ "${REPO_SYNC_STRATEGY}" = "mirror" ]; then
  if [ -n "$(git status --porcelain)" ]; then
    stash_ref="auto-update-pre-mirror-$(date -u +'%Y%m%dT%H%M%SZ')"
    git stash push -u -m "${stash_ref}" >/dev/null
    LOCAL_CHANGE_RESULT="stashed:${stash_ref}"
    log "Detected local changes, saved to stash (${stash_ref}) before mirror sync."
  fi
else
  if [ -n "$(git status --porcelain)" ]; then
    case "${LOCAL_CHANGES_POLICY}" in
      stash)
        stash_ref="auto-update-$(date -u +'%Y%m%dT%H%M%SZ')"
        git stash push -u -m "${stash_ref}" >/dev/null
        LOCAL_CHANGE_RESULT="stashed:${stash_ref}"
        log "Detected local changes, saved to stash (${stash_ref}) before pull."
        ;;
      commit)
        git add -A
        git commit -m "${LOCAL_CHANGES_COMMIT_MESSAGE}" >/dev/null
        local_checkpoint_sha="$(git rev-parse HEAD)"
        LOCAL_CHANGE_RESULT="committed:${local_checkpoint_sha}"
        PULL_MODE="rebase"
        log "Detected local changes, committed checkpoint (${local_checkpoint_sha}) before pull."
        ;;
      fail)
        append_update_audit "blocked_local_changes" "Working tree is dirty and LOCAL_CHANGES_POLICY=fail." "${LOCAL_SHA}" "${REMOTE_SHA}" "blocked"
        die "Working tree is dirty and LOCAL_CHANGES_POLICY=fail."
        ;;
      *)
        append_update_audit "blocked_local_changes" "Unknown LOCAL_CHANGES_POLICY value." "${LOCAL_SHA}" "${REMOTE_SHA}" "blocked"
        die "Unknown LOCAL_CHANGES_POLICY=${LOCAL_CHANGES_POLICY}. Use stash|commit|fail."
        ;;
    esac
  fi
fi

if [ "${UPDATE_APPROVAL_REQUIRED}" = "1" ] && [ "${apply_requested}" != "1" ]; then
  log "Update is available but waits for manual apply request."
  report_event "awaiting_approval" "auto-update" "Update available, waiting for admin apply request" "${LOCAL_SHA}" "${REMOTE_SHA}" "na"
  append_update_audit "available" "Update available. Waiting for admin apply request." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
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
append_update_audit "started" "Applying update and rebuilding services." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
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
if [ "${REPO_SYNC_STRATEGY}" = "mirror" ]; then
  # Make the server clone byte-for-byte aligned with origin/<branch>.
  git reset --hard "origin/${BRANCH}"
  git clean -fd
else
  if [ "${PULL_MODE}" = "rebase" ]; then
    git pull --rebase origin "${BRANCH}"
  else
    git pull --ff-only origin "${BRANCH}"
  fi
fi

deploy_current() {
  if [ "${MODE}" = "prod" ]; then
    bash ./scripts/sync-env.sh prod
    log "Running production preflight"
    bash ./scripts/preflight-prod.sh
    log "Rebuilding/restarting production stack"
    dc -f compose.yaml -f compose.prod.yaml up -d --build
    dc -f compose.yaml -f compose.prod.yaml ps
    MODE=prod HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh
  else
    bash ./scripts/sync-env.sh local
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
  append_update_audit "updated" "Update deployed and healthcheck passed." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
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
append_update_audit "failed" "Updated revision failed healthcheck." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
if rollback_to_previous; then
  report_event "failed_with_rollback" "auto-update" "Rollback to previous revision completed" "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_SHA}"
  append_update_audit "failed_with_rollback" "Update failed, rollback completed." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
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
append_update_audit "failed_no_rollback" "Update failed, rollback failed." "${LOCAL_SHA}" "${REMOTE_SHA}" "${LOCAL_CHANGE_RESULT}"
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
