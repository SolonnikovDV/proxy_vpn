#!/usr/bin/env bash
# Audit pull status and optionally apply update with local-change handling.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

BRANCH="${BRANCH:-main}"
APPLY_PULL="${APPLY_PULL:-1}" # 1 | 0
LOCAL_CHANGES_POLICY="${LOCAL_CHANGES_POLICY:-stash}" # stash | commit | fail
LOCAL_CHANGES_COMMIT_MESSAGE="${LOCAL_CHANGES_COMMIT_MESSAGE:-chore(pull-audit): checkpoint local changes before pull}"
AUDIT_DIR="${AUDIT_DIR:-logs}"
mkdir -p "${AUDIT_DIR}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_LOG="${AUDIT_DIR}/pull-audit-${TS}.log"

run_git() {
  git -c safe.directory="$(pwd)" "$@"
}

[ -d ".git" ] || die "Current path is not a git repository: $(pwd)"

{
  log "=== PULL AUDIT ${TS} ==="
  log "repo=$(pwd)"
  log "branch=${BRANCH}"
  old_head="$(run_git rev-parse HEAD)"
  log "old_head=${old_head}"
  run_git fetch origin "${BRANCH}"
  remote_head="$(run_git rev-parse "origin/${BRANCH}")"
  log "origin_${BRANCH}=${remote_head}"

  if [ "${old_head}" = "${remote_head}" ]; then
    log "result=no-update (already up-to-date)"
    log "AUDIT_LOG=${AUDIT_LOG}"
    exit 0
  fi

  log "result=update-available"
  log "--- commits to pull ---"
  run_git log --oneline --decorate "${old_head}..${remote_head}"
  log "--- files changed in pull ---"
  run_git diff --name-status "${old_head}..${remote_head}"

  if [ "${APPLY_PULL}" != "1" ]; then
    log "apply_pull=0 (audit only)"
    log "AUDIT_LOG=${AUDIT_LOG}"
    exit 0
  fi

  local_change_result="none"
  pull_mode="ff-only"
  if [ -n "$(run_git status --porcelain)" ]; then
    case "${LOCAL_CHANGES_POLICY}" in
      stash)
        stash_ref="pull-audit-${TS}"
        run_git stash push -u -m "${stash_ref}" >/dev/null
        local_change_result="stashed:${stash_ref}"
        ;;
      commit)
        run_git add -A
        run_git commit -m "${LOCAL_CHANGES_COMMIT_MESSAGE}" >/dev/null
        local_change_result="committed:$(run_git rev-parse --short HEAD)"
        pull_mode="rebase"
        ;;
      fail)
        die "Working tree is dirty and LOCAL_CHANGES_POLICY=fail."
        ;;
      *)
        die "Unknown LOCAL_CHANGES_POLICY=${LOCAL_CHANGES_POLICY}. Use stash|commit|fail."
        ;;
    esac
  fi
  log "local_changes=${local_change_result}"

  if [ "${pull_mode}" = "rebase" ]; then
    run_git pull --rebase origin "${BRANCH}"
  else
    run_git pull --ff-only origin "${BRANCH}"
  fi
  new_head="$(run_git rev-parse HEAD)"
  log "new_head=${new_head}"
  log "--- applied commits ---"
  run_git log --oneline --decorate "${old_head}..${new_head}"
  log "--- applied files ---"
  run_git diff --name-status "${old_head}..${new_head}"
  log "AUDIT_LOG=${AUDIT_LOG}"
} | tee "${AUDIT_LOG}"
