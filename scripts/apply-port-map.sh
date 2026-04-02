#!/usr/bin/env bash
# Maintain host-level client->runtime port mapping for Xray/WireGuard.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

is_valid_port() {
  local p="${1:-}"
  [[ "${p}" =~ ^[0-9]+$ ]] || return 1
  [ "${p}" -ge 1 ] && [ "${p}" -le 65535 ]
}

XRAY_PORT="${XRAY_PORT:-8443}"
WG_PORT="${WG_PORT:-51820}"
XRAY_CLIENT_PORT="${XRAY_CLIENT_PORT:-${XRAY_PORT}}"
WG_CLIENT_PORT="${WG_CLIENT_PORT:-${WG_PORT}}"
CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"

is_valid_port "${XRAY_PORT}" || die "Invalid XRAY_PORT=${XRAY_PORT}"
is_valid_port "${WG_PORT}" || die "Invalid WG_PORT=${WG_PORT}"
is_valid_port "${XRAY_CLIENT_PORT}" || die "Invalid XRAY_CLIENT_PORT=${XRAY_CLIENT_PORT}"
is_valid_port "${WG_CLIENT_PORT}" || die "Invalid WG_CLIENT_PORT=${WG_CLIENT_PORT}"
is_valid_port "${CADDY_HTTPS_PORT}" || die "Invalid CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}"

if [ "${XRAY_CLIENT_PORT}" = "${CADDY_HTTPS_PORT}" ] && [ "${XRAY_CLIENT_PORT}" != "${XRAY_PORT}" ]; then
  die "XRAY_CLIENT_PORT=${XRAY_CLIENT_PORT} conflicts with CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}."
fi

if ! command -v iptables >/dev/null 2>&1; then
  die "iptables is required for dynamic port mapping."
fi

iptables -t nat -N PROXY_VPN_PORTMAP >/dev/null 2>&1 || true
iptables -t nat -C PREROUTING -j PROXY_VPN_PORTMAP >/dev/null 2>&1 || iptables -t nat -I PREROUTING 1 -j PROXY_VPN_PORTMAP
iptables -t nat -F PROXY_VPN_PORTMAP

if [ "${XRAY_CLIENT_PORT}" != "${XRAY_PORT}" ]; then
  iptables -t nat -A PROXY_VPN_PORTMAP -p tcp --dport "${XRAY_CLIENT_PORT}" -j REDIRECT --to-ports "${XRAY_PORT}"
  log "Port map applied: Xray client ${XRAY_CLIENT_PORT}/tcp -> runtime ${XRAY_PORT}/tcp"
else
  log "Port map skipped: Xray client port equals runtime (${XRAY_PORT}/tcp)"
fi

if [ "${WG_CLIENT_PORT}" != "${WG_PORT}" ]; then
  iptables -t nat -A PROXY_VPN_PORTMAP -p udp --dport "${WG_CLIENT_PORT}" -j REDIRECT --to-ports "${WG_PORT}"
  log "Port map applied: WireGuard client ${WG_CLIENT_PORT}/udp -> runtime ${WG_PORT}/udp"
else
  log "Port map skipped: WireGuard client port equals runtime (${WG_PORT}/udp)"
fi

log "Dynamic port mapping is up to date."
