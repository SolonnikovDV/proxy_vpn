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

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running or not accessible."
fi

[ -f compose.prod.yaml ] || die "compose.prod.yaml not found."

# Load from .env if present; otherwise rely on runtime env vars (e.g. GitHub Actions secrets/vars).
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

export CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.prod}"
export CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
export CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
export XRAY_PORT="${XRAY_PORT:-8443}"
export WG_PORT="${WG_PORT:-51820}"
export APP_SECRET_KEY="${APP_SECRET_KEY:-}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

[ "${CADDYFILE_PATH}" = "Caddyfile.prod" ] || die "CADDYFILE_PATH must be Caddyfile.prod for production."
[ -n "${VPN_PANEL_DOMAIN:-}" ] || die "VPN_PANEL_DOMAIN is empty."
[ "${VPN_PANEL_DOMAIN}" != "panel.example.com" ] || die "Set a real VPN_PANEL_DOMAIN (not panel.example.com)."
[ "${VPN_PANEL_DOMAIN}" != "localhost" ] || die "VPN_PANEL_DOMAIN must be a real public domain."
[ -n "${APP_SECRET_KEY}" ] || die "APP_SECRET_KEY is empty."
[ "${APP_SECRET_KEY}" != "replace-with-long-random-secret" ] || die "Set real APP_SECRET_KEY in .env."
[ "${#APP_SECRET_KEY}" -ge 24 ] || die "APP_SECRET_KEY must be at least 24 characters."
[ -n "${ADMIN_PASSWORD}" ] || die "ADMIN_PASSWORD is empty."
[ "${ADMIN_PASSWORD}" != "replace-with-strong-admin-password" ] || die "Set real ADMIN_PASSWORD in .env."
[ "${#ADMIN_PASSWORD}" -ge 10 ] || die "ADMIN_PASSWORD must be at least 10 characters."

is_valid_port "${CADDY_HTTP_PORT}" || die "Invalid CADDY_HTTP_PORT=${CADDY_HTTP_PORT}"
is_valid_port "${CADDY_HTTPS_PORT}" || die "Invalid CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}"
is_valid_port "${XRAY_PORT}" || die "Invalid XRAY_PORT=${XRAY_PORT}"
is_valid_port "${WG_PORT}" || die "Invalid WG_PORT=${WG_PORT}"

[ "${CADDY_HTTPS_PORT}" != "${XRAY_PORT}" ] || die "CADDY_HTTPS_PORT and XRAY_PORT cannot be equal on same host."
[ -f wireguard/conf/wg0.conf ] || die "wireguard/conf/wg0.conf is missing."
[ -f xray/config.json ] || die "xray/config.json is missing."

if command -v getent >/dev/null 2>&1; then
  if ! getent ahostsv4 "${VPN_PANEL_DOMAIN}" >/dev/null 2>&1; then
    log "WARN: ${VPN_PANEL_DOMAIN} has no A record from this host view."
  fi
fi

dc -f compose.yaml -f compose.prod.yaml config -q

log "Preflight OK:"
log "  domain=${VPN_PANEL_DOMAIN}"
log "  caddy_http=${CADDY_HTTP_PORT} caddy_https=${CADDY_HTTPS_PORT} xray=${XRAY_PORT} wg=${WG_PORT}"
