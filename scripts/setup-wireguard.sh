#!/usr/bin/env bash
# Generate WireGuard server config and first client profile.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

DC_INITIALIZED=0
init_dc() {
  if [ "${DC_INITIALIZED}" = "1" ]; then
    return 0
  fi
  if docker compose version >/dev/null 2>&1; then
    dc() { docker compose "$@"; }
  elif command -v docker-compose >/dev/null 2>&1; then
    dc() { docker-compose "$@"; }
  else
    die "Neither host 'wg' nor Docker Compose is available for WireGuard key generation."
  fi
  DC_INITIALIZED=1
}

gen_wg_key() {
  if command -v wg >/dev/null 2>&1; then
    wg genkey | tr -d '\r\n'
    return 0
  fi
  init_dc
  dc run --rm --no-deps -T --entrypoint sh wireguard -lc "wg genkey" | tr -d '\r\n'
}

pub_from_priv() {
  local key="$1"
  if command -v wg >/dev/null 2>&1; then
    printf '%s' "${key}" | wg pubkey | tr -d '\r\n'
    return 0
  fi
  init_dc
  printf '%s' "${key}" | dc run --rm --no-deps -T --entrypoint sh wireguard -lc "wg pubkey" | tr -d '\r\n'
}

SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-}"
WG_PORT="${WG_PORT:-51820}"
WG_SERVER_CIDR="${WG_SERVER_CIDR:-10.13.0.1/24}"
WG_CLIENT_IP="${WG_CLIENT_IP:-10.13.0.2/32}"
WG_CLIENT_NAME="${WG_CLIENT_NAME:-client1}"
WG_CLIENT_DNS="${WG_CLIENT_DNS:-1.1.1.1,1.0.0.1}"
WG_CONFIG_DIR="${WG_CONFIG_DIR:-wireguard/conf}"
WG_SERVER_CONF="${WG_CONFIG_DIR}/wg0.conf"
WG_CLIENT_CONF="${WG_CONFIG_DIR}/${WG_CLIENT_NAME}.conf"

[ -n "${SERVER_PUBLIC_IP}" ] || die "Set SERVER_PUBLIC_IP (public IP or domain), e.g. SERVER_PUBLIC_IP=203.0.113.10"

mkdir -p "${WG_CONFIG_DIR}"

if [ -f "${WG_SERVER_CONF}" ]; then
  die "${WG_SERVER_CONF} already exists. Remove it manually if you want to regenerate."
fi

if command -v wg >/dev/null 2>&1; then
  log "Generating WireGuard keys using host wireguard-tools..."
else
  log "Generating WireGuard keys using wireguard container..."
fi
SERVER_PRIVATE_KEY="$(gen_wg_key)"
SERVER_PUBLIC_KEY="$(pub_from_priv "${SERVER_PRIVATE_KEY}")"
CLIENT_PRIVATE_KEY="$(gen_wg_key)"
CLIENT_PUBLIC_KEY="$(pub_from_priv "${CLIENT_PRIVATE_KEY}")"

cat > "${WG_SERVER_CONF}" <<EOF
[Interface]
Address = ${WG_SERVER_CIDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${WG_CLIENT_IP}
EOF

cat > "${WG_CLIENT_CONF}" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${WG_CLIENT_IP}
DNS = ${WG_CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${SERVER_PUBLIC_IP}:${WG_PORT}
PersistentKeepalive = 25
EOF

chmod 600 "${WG_SERVER_CONF}" "${WG_CLIENT_CONF}"

log "WireGuard config generated:"
log "  server: ${WG_SERVER_CONF}"
log "  client: ${WG_CLIENT_CONF}"
log "Next:"
log "  1) docker compose up -d wireguard"
log "  2) import ${WG_CLIENT_CONF} into your WireGuard app"
