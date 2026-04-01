#!/usr/bin/env bash
# Configure GitHub Actions variables/secrets for proxy-vpn.
# Compatible with old gh versions (uses gh api for variables).
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

command -v gh >/dev/null 2>&1 || die "gh CLI is required"

# Prefer explicit token provided by bootstrap/server automation.
if [ -n "${GH_TOKEN:-}" ]; then
  export GH_TOKEN
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  export GH_TOKEN="${GITHUB_TOKEN}"
fi

REPO="${REPO:-}"
if [ -z "${REPO}" ]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
fi
[ -n "${REPO}" ] || die "Cannot detect repository. Set REPO=owner/name"

if ! gh api "repos/${REPO}" >/dev/null 2>&1; then
  die "GitHub API cannot access repo ${REPO}. Check token permissions and repository access."
fi

MODE="${MODE:-set}" # set | delete

SSH_HOST="${SSH_HOST:-}"
SSH_USER="${SSH_USER:-}"
DEPLOY_PATH="${DEPLOY_PATH:-}"
VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
APP_SECRET_KEY_FILE="${APP_SECRET_KEY_FILE:-/etc/proxy-vpn/secrets/app_secret_key}"
ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE:-/etc/proxy-vpn/secrets/admin_password}"
RENDER_ENV_FROM_CI="${RENDER_ENV_FROM_CI:-0}"
PREFLIGHT_MAX_AGE_MIN="${PREFLIGHT_MAX_AGE_MIN:-60}"
DEPLOY_SSH_KEY_PATH="${DEPLOY_SSH_KEY_PATH:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
APP_SECRET_KEY="${APP_SECRET_KEY:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
CAPACITY_TARGET_ACTIVE_USERS="${CAPACITY_TARGET_ACTIVE_USERS:-15}"
CAPACITY_CPU_WARN_P95="${CAPACITY_CPU_WARN_P95:-70}"
CAPACITY_CPU_CRIT_P95="${CAPACITY_CPU_CRIT_P95:-80}"
CAPACITY_RAM_WARN_P95="${CAPACITY_RAM_WARN_P95:-80}"
CAPACITY_RAM_CRIT_P95="${CAPACITY_RAM_CRIT_P95:-85}"
CAPACITY_DISK_WARN_P95="${CAPACITY_DISK_WARN_P95:-85}"
CAPACITY_DISK_CRIT_P95="${CAPACITY_DISK_CRIT_P95:-92}"
DASHBOARD_REFRESH_SECONDS="${DASHBOARD_REFRESH_SECONDS:-30}"
LOGIN_MAX_ATTEMPTS="${LOGIN_MAX_ATTEMPTS:-5}"
LOGIN_WINDOW_MINUTES="${LOGIN_WINDOW_MINUTES:-10}"
LOGIN_LOCK_MINUTES="${LOGIN_LOCK_MINUTES:-15}"
SECURITY_GEOIP_ENABLED="${SECURITY_GEOIP_ENABLED:-1}"
SECURITY_GEOIP_TIMEOUT_SECONDS="${SECURITY_GEOIP_TIMEOUT_SECONDS:-1.5}"
SECURITY_DEFAULT_BLOCK_SECONDS="${SECURITY_DEFAULT_BLOCK_SECONDS:-900}"
SECURITY_HTTP_WINDOW_SECONDS="${SECURITY_HTTP_WINDOW_SECONDS:-10}"
SECURITY_HTTP_MAX_REQUESTS="${SECURITY_HTTP_MAX_REQUESTS:-120}"
SECURITY_PROBE_PATH_THRESHOLD="${SECURITY_PROBE_PATH_THRESHOLD:-12}"
SECURITY_BLOCK_SECONDS_DDOS="${SECURITY_BLOCK_SECONDS_DDOS:-600}"
SECURITY_BLOCK_SECONDS_BRUTE="${SECURITY_BLOCK_SECONDS_BRUTE:-900}"
SECURITY_SERVER_CHECK_INTERVAL_SECONDS="${SECURITY_SERVER_CHECK_INTERVAL_SECONDS:-60}"
SECURITY_SERVER_EVENT_COOLDOWN_SECONDS="${SECURITY_SERVER_EVENT_COOLDOWN_SECONDS:-300}"

set_repo_var() {
  local name="$1"
  local value="$2"
  gh api -X PATCH "repos/${REPO}/actions/variables/${name}" -f name="${name}" -f value="${value}" >/dev/null 2>&1 || \
    gh api -X POST "repos/${REPO}/actions/variables" -f name="${name}" -f value="${value}" >/dev/null
}

delete_repo_var() {
  local name="$1"
  gh api -X DELETE "repos/${REPO}/actions/variables/${name}" >/dev/null 2>&1 || true
}

set_repo_secret() {
  local name="$1"
  local value="$2"
  gh secret set "${name}" --repo "${REPO}" --body "${value}" >/dev/null
}

delete_repo_secret() {
  local name="$1"
  gh secret delete "${name}" --repo "${REPO}" >/dev/null 2>&1 || true
}

if [ "${MODE}" = "delete" ]; then
  for v in SSH_HOST SSH_USER DEPLOY_PATH VPN_PANEL_DOMAIN ADMIN_USERNAME ADMIN_EMAIL APP_SECRET_KEY_FILE ADMIN_PASSWORD_FILE RENDER_ENV_FROM_CI PREFLIGHT_MAX_AGE_MIN CAPACITY_TARGET_ACTIVE_USERS CAPACITY_CPU_WARN_P95 CAPACITY_CPU_CRIT_P95 CAPACITY_RAM_WARN_P95 CAPACITY_RAM_CRIT_P95 CAPACITY_DISK_WARN_P95 CAPACITY_DISK_CRIT_P95 DASHBOARD_REFRESH_SECONDS LOGIN_MAX_ATTEMPTS LOGIN_WINDOW_MINUTES LOGIN_LOCK_MINUTES SECURITY_GEOIP_ENABLED SECURITY_GEOIP_TIMEOUT_SECONDS SECURITY_DEFAULT_BLOCK_SECONDS SECURITY_HTTP_WINDOW_SECONDS SECURITY_HTTP_MAX_REQUESTS SECURITY_PROBE_PATH_THRESHOLD SECURITY_BLOCK_SECONDS_DDOS SECURITY_BLOCK_SECONDS_BRUTE SECURITY_SERVER_CHECK_INTERVAL_SECONDS SECURITY_SERVER_EVENT_COOLDOWN_SECONDS; do
    delete_repo_var "${v}"
  done
  for s in DEPLOY_SSH_KEY SSH_HOST SSH_USER SSH_PASSWORD APP_SECRET_KEY ADMIN_PASSWORD; do
    delete_repo_secret "${s}"
  done
  log "Deleted GitHub variables/secrets (best effort) for ${REPO}"
  exit 0
fi

[ -n "${SSH_HOST}" ] || die "SSH_HOST is required"
[ -n "${SSH_USER}" ] || die "SSH_USER is required"
[ -n "${DEPLOY_PATH}" ] || die "DEPLOY_PATH is required"
[ -n "${VPN_PANEL_DOMAIN}" ] || die "VPN_PANEL_DOMAIN is required"

set_repo_var SSH_HOST "${SSH_HOST}"
set_repo_var SSH_USER "${SSH_USER}"
set_repo_var DEPLOY_PATH "${DEPLOY_PATH}"
set_repo_var VPN_PANEL_DOMAIN "${VPN_PANEL_DOMAIN}"
set_repo_var ADMIN_USERNAME "${ADMIN_USERNAME}"
set_repo_var ADMIN_EMAIL "${ADMIN_EMAIL}"
set_repo_var APP_SECRET_KEY_FILE "${APP_SECRET_KEY_FILE}"
set_repo_var ADMIN_PASSWORD_FILE "${ADMIN_PASSWORD_FILE}"
set_repo_var RENDER_ENV_FROM_CI "${RENDER_ENV_FROM_CI}"
set_repo_var PREFLIGHT_MAX_AGE_MIN "${PREFLIGHT_MAX_AGE_MIN}"
set_repo_var CAPACITY_TARGET_ACTIVE_USERS "${CAPACITY_TARGET_ACTIVE_USERS}"
set_repo_var CAPACITY_CPU_WARN_P95 "${CAPACITY_CPU_WARN_P95}"
set_repo_var CAPACITY_CPU_CRIT_P95 "${CAPACITY_CPU_CRIT_P95}"
set_repo_var CAPACITY_RAM_WARN_P95 "${CAPACITY_RAM_WARN_P95}"
set_repo_var CAPACITY_RAM_CRIT_P95 "${CAPACITY_RAM_CRIT_P95}"
set_repo_var CAPACITY_DISK_WARN_P95 "${CAPACITY_DISK_WARN_P95}"
set_repo_var CAPACITY_DISK_CRIT_P95 "${CAPACITY_DISK_CRIT_P95}"
set_repo_var DASHBOARD_REFRESH_SECONDS "${DASHBOARD_REFRESH_SECONDS}"
set_repo_var LOGIN_MAX_ATTEMPTS "${LOGIN_MAX_ATTEMPTS}"
set_repo_var LOGIN_WINDOW_MINUTES "${LOGIN_WINDOW_MINUTES}"
set_repo_var LOGIN_LOCK_MINUTES "${LOGIN_LOCK_MINUTES}"
set_repo_var SECURITY_GEOIP_ENABLED "${SECURITY_GEOIP_ENABLED}"
set_repo_var SECURITY_GEOIP_TIMEOUT_SECONDS "${SECURITY_GEOIP_TIMEOUT_SECONDS}"
set_repo_var SECURITY_DEFAULT_BLOCK_SECONDS "${SECURITY_DEFAULT_BLOCK_SECONDS}"
set_repo_var SECURITY_HTTP_WINDOW_SECONDS "${SECURITY_HTTP_WINDOW_SECONDS}"
set_repo_var SECURITY_HTTP_MAX_REQUESTS "${SECURITY_HTTP_MAX_REQUESTS}"
set_repo_var SECURITY_PROBE_PATH_THRESHOLD "${SECURITY_PROBE_PATH_THRESHOLD}"
set_repo_var SECURITY_BLOCK_SECONDS_DDOS "${SECURITY_BLOCK_SECONDS_DDOS}"
set_repo_var SECURITY_BLOCK_SECONDS_BRUTE "${SECURITY_BLOCK_SECONDS_BRUTE}"
set_repo_var SECURITY_SERVER_CHECK_INTERVAL_SECONDS "${SECURITY_SERVER_CHECK_INTERVAL_SECONDS}"
set_repo_var SECURITY_SERVER_EVENT_COOLDOWN_SECONDS "${SECURITY_SERVER_EVENT_COOLDOWN_SECONDS}"

if [ -n "${DEPLOY_SSH_KEY_PATH}" ]; then
  [ -f "${DEPLOY_SSH_KEY_PATH}" ] || die "DEPLOY_SSH_KEY_PATH not found: ${DEPLOY_SSH_KEY_PATH}"
  gh secret set DEPLOY_SSH_KEY --repo "${REPO}" < "${DEPLOY_SSH_KEY_PATH}"
  log "Set DEPLOY_SSH_KEY secret from ${DEPLOY_SSH_KEY_PATH}"
else
  log "DEPLOY_SSH_KEY_PATH is empty, skip DEPLOY_SSH_KEY secret"
fi

set_repo_secret SSH_HOST "${SSH_HOST}"
set_repo_secret SSH_USER "${SSH_USER}"
if [ -n "${SSH_PASSWORD}" ]; then
  set_repo_secret SSH_PASSWORD "${SSH_PASSWORD}"
  log "Set SSH_HOST/SSH_USER/SSH_PASSWORD secrets"
else
  log "Set SSH_HOST/SSH_USER secrets; SSH_PASSWORD is empty and was skipped"
fi

if [ -n "${APP_SECRET_KEY}" ]; then
  set_repo_secret APP_SECRET_KEY "${APP_SECRET_KEY}"
  log "Set APP_SECRET_KEY secret (inline render mode)"
else
  log "APP_SECRET_KEY is empty, skip APP_SECRET_KEY secret"
fi

if [ -n "${ADMIN_PASSWORD}" ]; then
  set_repo_secret ADMIN_PASSWORD "${ADMIN_PASSWORD}"
  log "Set ADMIN_PASSWORD secret (inline render mode)"
else
  log "ADMIN_PASSWORD is empty, skip ADMIN_PASSWORD secret"
fi

log "Configured GitHub Actions variables/secrets for ${REPO}"
