#!/usr/bin/env bash
# Restore critical proxy-vpn backup: DB, configs, env, optional secrets.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

ARCHIVE_PATH="${1:-}"
[ -n "${ARCHIVE_PATH}" ] || die "Usage: bash ./scripts/restore-critical.sh <backup-archive.tar.gz>"
[ -f "${ARCHIVE_PATH}" ] || die "Backup archive not found: ${ARCHIVE_PATH}"

MODE="${MODE:-prod}"
START_AFTER_RESTORE="${START_AFTER_RESTORE:-1}"
RESTORE_SECRETS="${RESTORE_SECRETS:-1}"

if docker compose version >/dev/null 2>&1; then
  dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  dc() { docker-compose "$@"; }
else
  die "Docker Compose not found (need 'docker compose' or 'docker-compose')."
fi

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running or not accessible."
fi

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}" >/dev/null 2>&1 || true' EXIT

log "Extracting backup archive..."
tar -xzf "${ARCHIVE_PATH}" -C "${tmp_root}"
payload="${tmp_root}/payload"
[ -d "${payload}" ] || die "Invalid backup archive structure (missing payload dir)"

log "Stopping stack before restore..."
bash ./scripts/run.sh "${MODE}" down

log "Restoring repository runtime files..."
[ -f "${payload}/repo/.env" ] && cp -f "${payload}/repo/.env" ".env"
if [ -d "${payload}/repo/xray" ]; then
  rm -rf "./xray"
  cp -a "${payload}/repo/xray" "./xray"
fi
if [ -d "${payload}/repo/wireguard-conf" ]; then
  mkdir -p "./wireguard"
  rm -rf "./wireguard/conf"
  cp -a "${payload}/repo/wireguard-conf" "./wireguard/conf"
fi
if [ -d "${payload}/repo/logs" ]; then
  mkdir -p "./logs"
  cp -a "${payload}/repo/logs/." "./logs/"
fi
if [ -d "${payload}/repo/caddy-data" ]; then
  log "Restoring caddy data volume..."
  docker run --rm \
    -v proxy-vpn_caddy_data:/data \
    -v "${payload}/repo:/backup" \
    alpine:3.20 sh -lc 'rm -rf /data/* && cp -a /backup/caddy-data/. /data/ 2>/dev/null || true'
fi
if [ -d "${payload}/repo/caddy-config" ]; then
  log "Restoring caddy config volume..."
  docker run --rm \
    -v proxy-vpn_caddy_config:/data \
    -v "${payload}/repo:/backup" \
    alpine:3.20 sh -lc 'rm -rf /data/* && cp -a /backup/caddy-config/. /data/ 2>/dev/null || true'
fi

log "Restoring SQLite database into docker volume..."
[ -f "${payload}/data/app.db" ] || die "Backup does not contain app.db"
docker run --rm \
  -v proxy-vpn_api_data:/data \
  -v "${payload}/data:/backup" \
  alpine:3.20 sh -lc 'cp -f /backup/app.db /data/app.db && chmod 600 /data/app.db'

if [ -f "${payload}/data/security.db" ]; then
  log "Restoring security-guard database into docker volume..."
  docker run --rm \
    -v proxy-vpn_security_data:/data \
    -v "${payload}/data:/backup" \
    alpine:3.20 sh -lc 'cp -f /backup/security.db /data/security.db && chmod 600 /data/security.db'
fi

if [ "${RESTORE_SECRETS}" = "1" ] && [ -f "${payload}/meta/secrets-list.txt" ] && [ -d "${payload}/secrets" ]; then
  log "Restoring external secret files..."
  while IFS='=' read -r key secret_path; do
    [ -n "${secret_path}" ] || continue
    src_file="${payload}/secrets/${key}"
    if [ -f "${src_file}" ]; then
      install -d -m 700 "$(dirname "${secret_path}")"
      cp -f "${src_file}" "${secret_path}"
      chmod 600 "${secret_path}"
      chown root:root "${secret_path}" 2>/dev/null || true
    fi
  done < "${payload}/meta/secrets-list.txt"
fi

if [ "${START_AFTER_RESTORE}" = "1" ]; then
  log "Starting stack after restore..."
  bash ./scripts/run.sh "${MODE}" up
fi

log "Restore completed from: ${ARCHIVE_PATH}"
