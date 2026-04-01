#!/usr/bin/env bash
# Generate Xray VLESS+REALITY production config and client connection data.
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

XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-xray/config.json}"
XRAY_CLIENT_INFO_PATH="${XRAY_CLIENT_INFO_PATH:-xray/client-connection.txt}"
XRAY_PORT="${XRAY_PORT:-8443}"
XRAY_REALITY_DEST="${XRAY_REALITY_DEST:-www.cloudflare.com:443}"
XRAY_REALITY_SERVER_NAME="${XRAY_REALITY_SERVER_NAME:-www.cloudflare.com}"
XRAY_CLIENT_EMAIL="${XRAY_CLIENT_EMAIL:-client1@proxy-vpn}"
SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-}"

[ -n "${SERVER_PUBLIC_IP}" ] || die "Set SERVER_PUBLIC_IP (public IP or domain), e.g. SERVER_PUBLIC_IP=203.0.113.10"

mkdir -p xray

log "Generating REALITY x25519 keypair using xray image..."
KEYS_OUTPUT="$(docker run --rm ghcr.io/xtls/xray-core:latest x25519 2>&1 || true)"
REALITY_PRIVATE_KEY="$(python3 - "${KEYS_OUTPUT}" <<'PY'
import re
import sys

text = sys.argv[1] if len(sys.argv) > 1 else ""
m = re.search(r"private\s*key\s*:\s*([A-Za-z0-9+/_=-]{20,})", text, flags=re.IGNORECASE)
if not m:
    m = re.search(r"privatekey\s*:\s*([A-Za-z0-9+/_=-]{20,})", text, flags=re.IGNORECASE)
if m:
    print(m.group(1).strip())
PY
)"
REALITY_PUBLIC_KEY="$(python3 - "${KEYS_OUTPUT}" <<'PY'
import re
import sys

text = sys.argv[1] if len(sys.argv) > 1 else ""
# Xray output varies by version:
# - "Public key: ..."
# - "PublicKey: ..."
# - "Password (PublicKey): ..."
m = re.search(r"public\s*key\s*:\s*([A-Za-z0-9+/_=-]{20,})", text, flags=re.IGNORECASE)
if not m:
    m = re.search(r"publickey\s*:\s*([A-Za-z0-9+/_=-]{20,})", text, flags=re.IGNORECASE)
if not m:
    m = re.search(r"password\s*\(\s*publickey\s*\)\s*:\s*([A-Za-z0-9+/_=-]{20,})", text, flags=re.IGNORECASE)
if m:
    print(m.group(1).strip())
PY
)"

[ -n "${REALITY_PRIVATE_KEY}" ] || die "Failed to generate REALITY private key. xray output: ${KEYS_OUTPUT}"
[ -n "${REALITY_PUBLIC_KEY}" ] || die "Failed to generate REALITY public key. xray output: ${KEYS_OUTPUT}"

CLIENT_UUID="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
SHORT_ID="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"

cat > "${XRAY_CONFIG_PATH}" <<EOF
{
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "stats": {},
  "policy": {
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    },
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    }
  },
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${CLIENT_UUID}",
            "flow": "xtls-rprx-vision",
            "email": "${XRAY_CLIENT_EMAIL}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${XRAY_REALITY_DEST}",
          "xver": 0,
          "serverNames": [
            "${XRAY_REALITY_SERVER_NAME}"
          ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "tag": "vless-reality-in"
    },
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api-in"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api-in"
        ],
        "outboundTag": "api"
      }
    ]
  },
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ]
}
EOF

cat > "${XRAY_CLIENT_INFO_PATH}" <<EOF
Xray VLESS+REALITY client connection
====================================
Server address: ${SERVER_PUBLIC_IP}
Server port: ${XRAY_PORT}
UUID: ${CLIENT_UUID}
Flow: xtls-rprx-vision
Security: reality
SNI: ${XRAY_REALITY_SERVER_NAME}
Public key: ${REALITY_PUBLIC_KEY}
Short ID: ${SHORT_ID}

Example URI (for v2rayN/NekoBox/etc):
vless://${CLIENT_UUID}@${SERVER_PUBLIC_IP}:${XRAY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${XRAY_REALITY_SERVER_NAME}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#proxy-vpn-client1
EOF

# Xray container may run as non-root user; config must be world-readable.
chmod 644 "${XRAY_CONFIG_PATH}"
chmod 600 "${XRAY_CLIENT_INFO_PATH}"

log "Xray config generated:"
log "  config: ${XRAY_CONFIG_PATH}"
log "  client: ${XRAY_CLIENT_INFO_PATH}"
log "Next:"
log "  1) docker compose up -d xray"
log "  2) import client URI from ${XRAY_CLIENT_INFO_PATH}"
