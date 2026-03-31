#!/usr/bin/env bash
# Render production .env from runtime environment variables (CI/CD friendly).
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    die "Required env var is missing: ${name}"
  fi
}

# Required for production.
require_var VPN_PANEL_DOMAIN
require_var APP_SECRET_KEY
require_var ADMIN_PASSWORD

# Optional with defaults.
CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.prod}"
CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
XRAY_PORT="${XRAY_PORT:-8443}"
WG_PORT="${WG_PORT:-51820}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"

cat > .env <<EOF
CADDYFILE_PATH=${CADDYFILE_PATH}
VPN_PANEL_DOMAIN=${VPN_PANEL_DOMAIN}
CADDY_HTTP_PORT=${CADDY_HTTP_PORT}
CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}
XRAY_PORT=${XRAY_PORT}
WG_PORT=${WG_PORT}
APP_SECRET_KEY=${APP_SECRET_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF

chmod 600 .env
log "Rendered .env from runtime environment."
