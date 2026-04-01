#!/usr/bin/env bash
# Validate production environment without deployment.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found (need 'docker compose' or 'docker-compose')."
fi

is_valid_port() {
  local p="${1:-}"
  [ -n "${p}" ] || return 1
  case "${p}" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${p}" -ge 1 ] && [ "${p}" -le 65535 ]
}

assert_caddy_route_present() {
  local route="$1"
  local file="$2"
  rg -n "handle[[:space:]]+${route}(\\*|[[:space:]]|\\{)" "${file}" >/dev/null 2>&1 \
    || die "${file} is missing required route matcher for ${route}"
}

read_secret_value() {
  local raw="${1:-}"
  local file_path="${2:-}"
  if [ -n "${raw}" ]; then
    printf '%s' "${raw}"
    return 0
  fi
  if [ -n "${file_path}" ]; then
    [ -f "${file_path}" ] || die "Secret file not found: ${file_path}"
    local v
    v="$(tr -d '\r' < "${file_path}")"
    v="${v%$'\n'}"
    printf '%s' "${v}"
    return 0
  fi
  printf ''
}

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running or not accessible."
fi

[ -f compose.prod.yaml ] || die "compose.prod.yaml not found."

# Ensure runtime .env exists for docker compose env_file contract.
if [ ! -f .env ]; then
  log ".env is missing, generating from production template..."
  bash ./scripts/sync-env.sh prod
fi

# Load from .env if present; otherwise rely on runtime env vars (e.g. GitHub Actions secrets/vars).
fallback_vpn_panel_domain="${VPN_PANEL_DOMAIN:-}"
fallback_app_secret_key="${APP_SECRET_KEY:-}"
fallback_admin_password="${ADMIN_PASSWORD:-}"
fallback_app_secret_key_file="${APP_SECRET_KEY_FILE:-}"
fallback_admin_password_file="${ADMIN_PASSWORD_FILE:-}"
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-${fallback_vpn_panel_domain}}"
APP_SECRET_KEY="${APP_SECRET_KEY:-${fallback_app_secret_key}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${fallback_admin_password}}"
APP_SECRET_KEY_FILE="${APP_SECRET_KEY_FILE:-${fallback_app_secret_key_file}}"
ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE:-${fallback_admin_password_file}}"

# If .env contains placeholder domain, prefer runtime-provided value (e.g. SSH_HOST fallback from CI workflow).
if [ "${VPN_PANEL_DOMAIN:-}" = "panel.example.com" ] || [ "${VPN_PANEL_DOMAIN:-}" = "localhost" ]; then
  if [ -n "${fallback_vpn_panel_domain:-}" ] && [ "${fallback_vpn_panel_domain}" != "panel.example.com" ] && [ "${fallback_vpn_panel_domain}" != "localhost" ]; then
    VPN_PANEL_DOMAIN="${fallback_vpn_panel_domain}"
  fi
fi

export CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.prod}"
export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
export CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
export XRAY_PORT="${XRAY_PORT:-8443}"
export WG_PORT="${WG_PORT:-51820}"

[ "${CADDYFILE_PATH}" = "Caddyfile.prod" ] || die "CADDYFILE_PATH must be Caddyfile.prod for production."
[ -n "${VPN_PANEL_DOMAIN:-}" ] || die "VPN_PANEL_DOMAIN is empty."
[ "${VPN_PANEL_DOMAIN}" != "panel.example.com" ] || die "Set a real VPN_PANEL_DOMAIN (not panel.example.com)."
[ "${VPN_PANEL_DOMAIN}" != "localhost" ] || die "VPN_PANEL_DOMAIN must be a real public domain."
APP_SECRET_VALUE="$(read_secret_value "${APP_SECRET_KEY}" "${APP_SECRET_KEY_FILE}")"
ADMIN_PASSWORD_VALUE="$(read_secret_value "${ADMIN_PASSWORD}" "${ADMIN_PASSWORD_FILE}")"
[ -n "${APP_SECRET_VALUE}" ] || die "APP_SECRET_KEY/APP_SECRET_KEY_FILE is empty."
[ "${APP_SECRET_VALUE}" != "replace-with-long-random-secret" ] || die "Set real APP_SECRET_KEY (or APP_SECRET_KEY_FILE)."
[ "${#APP_SECRET_VALUE}" -ge 24 ] || die "APP_SECRET_KEY must be at least 24 characters."
[ -n "${ADMIN_PASSWORD_VALUE}" ] || die "ADMIN_PASSWORD/ADMIN_PASSWORD_FILE is empty."
[ "${ADMIN_PASSWORD_VALUE}" != "replace-with-strong-admin-password" ] || die "Set real ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE)."
[ "${#ADMIN_PASSWORD_VALUE}" -ge 10 ] || die "ADMIN_PASSWORD must be at least 10 characters."

is_valid_port "${CADDY_HTTP_PORT}" || die "Invalid CADDY_HTTP_PORT=${CADDY_HTTP_PORT}"
is_valid_port "${CADDY_HTTPS_PORT}" || die "Invalid CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}"
is_valid_port "${XRAY_PORT}" || die "Invalid XRAY_PORT=${XRAY_PORT}"
is_valid_port "${WG_PORT}" || die "Invalid WG_PORT=${WG_PORT}"

[ "${CADDY_HTTPS_PORT}" != "${XRAY_PORT}" ] || die "CADDY_HTTPS_PORT and XRAY_PORT cannot be equal on same host."
[ -f wireguard/conf/wg0.conf ] || die "wireguard/conf/wg0.conf is missing."
[ -f xray/config.json ] || die "xray/config.json is missing."
[ -f "caddy/${CADDYFILE_PATH}" ] || die "Caddy file is missing: caddy/${CADDYFILE_PATH}"

# Catch UI route regressions before deployment.
assert_caddy_route_present "/admin" "caddy/${CADDYFILE_PATH}"
assert_caddy_route_present "/about" "caddy/${CADDYFILE_PATH}"
assert_caddy_route_present "/license" "caddy/${CADDYFILE_PATH}"

if command -v getent >/dev/null 2>&1; then
  if ! getent ahostsv4 "${VPN_PANEL_DOMAIN}" >/dev/null 2>&1; then
    log "WARN: ${VPN_PANEL_DOMAIN} has no A record from this host view."
  fi
fi

dc -f compose.yaml -f compose.prod.yaml config -q

log "Preflight OK:"
log "  domain=${VPN_PANEL_DOMAIN}"
log "  caddy_http=${CADDY_HTTP_PORT} caddy_https=${CADDY_HTTPS_PORT} xray=${XRAY_PORT} wg=${WG_PORT}"
