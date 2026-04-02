#!/usr/bin/env bash
# Batch-generate clients for WireGuard and Xray(REALITY) in one run.
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
    die "Neither host 'wg' nor Docker Compose is available for WireGuard key operations."
  fi
  DC_INITIALIZED=1
}

wg_pub_from_priv() {
  local key="$1"
  if command -v wg >/dev/null 2>&1; then
    printf '%s' "${key}" | wg pubkey | tr -d '\r\n'
    return 0
  fi
  init_dc
  printf '%s' "${key}" | dc run --rm --no-deps -T --entrypoint sh wireguard -lc "wg pubkey" | tr -d '\r\n'
}

wg_genkey_value() {
  if command -v wg >/dev/null 2>&1; then
    wg genkey | tr -d '\r\n'
    return 0
  fi
  init_dc
  dc run --rm --no-deps -T --entrypoint sh wireguard -lc "wg genkey" | tr -d '\r\n'
}

CLIENT_NAMES="${CLIENT_NAMES:-}"
SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-}"
WG_PORT="${WG_PORT:-51820}"
WG_CLIENT_PORT="${WG_CLIENT_PORT:-${WG_PORT}}"
WG_CLIENT_DNS="${WG_CLIENT_DNS:-1.1.1.1,1.0.0.1}"
WG_BASE_PREFIX="${WG_BASE_PREFIX:-10.13.0}"
WG_START_HOST="${WG_START_HOST:-20}"
XRAY_PORT="${XRAY_PORT:-8443}"
XRAY_CLIENT_PORT="${XRAY_CLIENT_PORT:-${XRAY_PORT}}"

[ -n "${CLIENT_NAMES}" ] || die "Set CLIENT_NAMES, e.g. CLIENT_NAMES=alice,bob,charlie"
[ -n "${SERVER_PUBLIC_IP}" ] || die "Set SERVER_PUBLIC_IP, e.g. SERVER_PUBLIC_IP=203.0.113.10"
[ -f wireguard/conf/wg0.conf ] || die "wireguard/conf/wg0.conf missing. Run setup-wireguard.sh first."
[ -f xray/config.json ] || die "xray/config.json missing. Run setup-xray-reality.sh first."
[ -f xray/client-connection.txt ] || die "xray/client-connection.txt missing. Run setup-xray-reality.sh first."

mkdir -p wireguard/conf xray/clients

SERVER_PRIVATE_KEY="$(awk -F'= ' '/^PrivateKey/{print $2; exit}' wireguard/conf/wg0.conf | tr -d '[:space:]')"
[ -n "${SERVER_PRIVATE_KEY}" ] || die "Cannot read server PrivateKey from wireguard/conf/wg0.conf"
SERVER_PUBLIC_KEY="$(wg_pub_from_priv "${SERVER_PRIVATE_KEY}")"
[ -n "${SERVER_PUBLIC_KEY}" ] || die "Cannot derive WireGuard server public key."

XRAY_SNI="$(awk -F': ' '/^SNI:/{print $2; exit}' xray/client-connection.txt | tr -d '\r\n')"
XRAY_PBK="$(awk -F': ' '/^Public key:/{print $2; exit}' xray/client-connection.txt | tr -d '\r\n')"
XRAY_SID="$(awk -F': ' '/^Short ID:/{print $2; exit}' xray/client-connection.txt | tr -d '\r\n')"
[ -n "${XRAY_SNI}" ] || die "Cannot read SNI from xray/client-connection.txt"
[ -n "${XRAY_PBK}" ] || die "Cannot read REALITY public key from xray/client-connection.txt"
[ -n "${XRAY_SID}" ] || die "Cannot read short id from xray/client-connection.txt"

IFS=',' read -r -a RAW_NAMES <<< "${CLIENT_NAMES}"
CLIENT_LIST=()
for raw in "${RAW_NAMES[@]}"; do
  name="$(printf '%s' "${raw}" | tr -d '[:space:]')"
  [ -n "${name}" ] && CLIENT_LIST+=("${name}")
done
[ "${#CLIENT_LIST[@]}" -gt 0 ] || die "CLIENT_NAMES parsed empty."

WG_INDEX="${WG_START_HOST}"
for name in "${CLIENT_LIST[@]}"; do
  wg_client_conf="wireguard/conf/${name}.conf"
  xray_client_file="xray/clients/${name}.txt"

  if [ -f "${wg_client_conf}" ] || [ -f "${xray_client_file}" ]; then
    die "Client files already exist for '${name}'. Remove or rename before rerun."
  fi

  wg_priv="$(wg_genkey_value)"
  wg_pub="$(wg_pub_from_priv "${wg_priv}")"
  wg_ip="${WG_BASE_PREFIX}.${WG_INDEX}/32"

  cat >> wireguard/conf/wg0.conf <<EOF

[Peer]
PublicKey = ${wg_pub}
AllowedIPs = ${wg_ip}
EOF

  cat > "${wg_client_conf}" <<EOF
[Interface]
PrivateKey = ${wg_priv}
Address = ${wg_ip}
DNS = ${WG_CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${SERVER_PUBLIC_IP}:${WG_CLIENT_PORT}
PersistentKeepalive = 25
EOF

  client_uuid="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
  client_email="${name}@proxy-vpn"

  python3 - "$client_uuid" "$client_email" <<'PY'
import json, sys
uuid = sys.argv[1]
email = sys.argv[2]
path = "xray/config.json"
with open(path, "r", encoding="utf-8") as f:
    cfg = json.load(f)
clients = cfg["inbounds"][0]["settings"].get("clients", [])
if any(c.get("email") == email for c in clients):
    raise SystemExit(f"Client email already exists in xray/config.json: {email}")
clients.append({"id": uuid, "flow": "xtls-rprx-vision", "email": email})
cfg["inbounds"][0]["settings"]["clients"] = clients
with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

  cat > "${xray_client_file}" <<EOF
Client: ${name}
Server address: ${SERVER_PUBLIC_IP}
Server port: ${XRAY_CLIENT_PORT}
UUID: ${client_uuid}
Flow: xtls-rprx-vision
Security: reality
SNI: ${XRAY_SNI}
Public key: ${XRAY_PBK}
Short ID: ${XRAY_SID}
URI:
vless://${client_uuid}@${SERVER_PUBLIC_IP}:${XRAY_CLIENT_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${XRAY_SNI}&fp=chrome&pbk=${XRAY_PBK}&sid=${XRAY_SID}&type=tcp#proxy-vpn-${name}
EOF

  chmod 600 "${wg_client_conf}" "${xray_client_file}"
  WG_INDEX=$((WG_INDEX + 1))
done

chmod 600 wireguard/conf/wg0.conf xray/config.json

log "Batch completed for ${#CLIENT_LIST[@]} clients."
log "WireGuard client configs: wireguard/conf/<name>.conf"
log "Xray client files: xray/clients/<name>.txt"
log "Apply runtime changes:"
log "  docker compose up -d wireguard xray"
