#!/usr/bin/env bash
# Create backup of critical proxy-vpn data: DB, configs, env, secrets, state logs.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { LAST_ERROR="$*"; log "ERROR: $*"; exit 1; }

BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION_COUNT="${RETENTION_COUNT:-14}"
INCLUDE_LOGS="${INCLUDE_LOGS:-1}"
MODE="${MODE:-prod}"
CHECK_INTEGRITY="${CHECK_INTEGRITY:-1}"
BACKUP_STATUS_PATH="${BACKUP_STATUS_PATH:-logs/backup-status.json}"
LAST_ERROR=""
ARCHIVE_CREATED=""

timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
archive_name="proxy-vpn-backup-${timestamp}.tar.gz"
tmp_root="$(mktemp -d)"
stage="${tmp_root}/stage"
payload="${stage}/payload"
mkdir -p "${payload}/repo" "${payload}/data" "${payload}/meta" "${BACKUP_DIR}"

cleanup() {
  rm -rf "${tmp_root}" >/dev/null 2>&1 || true
}

write_backup_status() {
  local backup_status="$1"
  local message="$2"
  local integrity_status="$3"
  local integrity_reason="$4"
  local archive_path="$5"
  mkdir -p "$(dirname "${BACKUP_STATUS_PATH}")"
  python3 - "${BACKUP_STATUS_PATH}" "${backup_status}" "${message}" "${integrity_status}" "${integrity_reason}" "${archive_path}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
backup_status = sys.argv[2]
message = sys.argv[3]
integrity_status = sys.argv[4]
integrity_reason = sys.argv[5]
archive_path = sys.argv[6]
now = datetime.now(timezone.utc).isoformat()
prev = {}
if path.exists():
    try:
        prev = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        prev = {}
if not isinstance(prev, dict):
    prev = {}
last_success = prev.get("last_success_at")
if backup_status == "success":
    last_success = now
data = {
    "status": "ok" if backup_status == "success" else "degraded",
    "backup_status": backup_status,
    "updated_at": now,
    "last_success_at": last_success,
    "message": message,
    "integrity": {
        "status": integrity_status,
        "reason": integrity_reason,
    },
    "archive_path": archive_path or prev.get("archive_path", ""),
}
path.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
PY
}

on_error() {
  local cmd="${BASH_COMMAND:-unknown}"
  if [ -z "${LAST_ERROR}" ]; then
    LAST_ERROR="command failed: ${cmd}"
  fi
}

on_exit() {
  local rc=$?
  local integrity_status="skipped"
  local integrity_reason="integrity gate disabled"
  if [ "${CHECK_INTEGRITY}" = "1" ]; then
    integrity_status="ok"
    integrity_reason="runtime integrity check passed"
  fi
  if [ "${rc}" -eq 0 ]; then
    write_backup_status "success" "Backup completed successfully." "${integrity_status}" "${integrity_reason}" "${ARCHIVE_CREATED}"
  else
    if [ "${CHECK_INTEGRITY}" = "1" ] && [[ "${LAST_ERROR}" == Integrity\ gate\ failed* ]]; then
      integrity_status="failed"
      integrity_reason="${LAST_ERROR#Integrity gate failed: }"
    fi
    write_backup_status "failed" "${LAST_ERROR:-backup failed}" "${integrity_status}" "${integrity_reason}" "${ARCHIVE_CREATED}"
  fi
  cleanup
}

trap on_error ERR
trap on_exit EXIT

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

git_sha="$(git rev-parse HEAD 2>/dev/null || echo na)"
git_branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo na)"

if [ "${CHECK_INTEGRITY}" = "1" ]; then
  log "Running integrity gate before backup..."
  integrity_output=""
  if ! integrity_output="$(INTEGRITY_SCOPE=runtime bash ./scripts/integrity-check.sh 2>&1)"; then
    integrity_reason="$(printf '%s' "${integrity_output}" | awk 'NF{line=$0} END{print line}')"
    die "Integrity gate failed: ${integrity_reason:-unknown reason}"
  fi
  printf '%s\n' "${integrity_output}"
fi

copy_db_from_volume() {
  log "Using Docker volume backup path..."
  docker run --rm \
    -v proxy-vpn_api_data:/data \
    -v "${payload}/data:/backup" \
    alpine:3.20 sh -lc 'if [ -f /data/app.db ]; then cp -f /data/app.db /backup/app.db; fi'
}

if docker ps --format '{{.Names}}' | grep -Eq '^proxy-vpn-api$'; then
  log "Backing up SQLite database from running api container..."
  docker exec proxy-vpn-api python - <<'PY'
import sqlite3
src = sqlite3.connect('/data/app.db')
dst = sqlite3.connect('/tmp/app-backup.db')
src.backup(dst)
dst.close()
src.close()
PY
  if docker cp "proxy-vpn-api:/tmp/app-backup.db" "${payload}/data/app.db"; then
    docker exec proxy-vpn-api rm -f /tmp/app-backup.db >/dev/null 2>&1 || true
  else
    log "Container snapshot file unavailable, fallback to volume backup."
    copy_db_from_volume
  fi
else
  log "Api container is not running."
  copy_db_from_volume
fi

[ -f "${payload}/data/app.db" ] || die "app.db not found in runtime sources"

docker run --rm \
  -v proxy-vpn_security_data:/data \
  -v "${payload}/data:/backup" \
  alpine:3.20 sh -lc 'if [ -f /data/security.db ]; then cp -f /data/security.db /backup/security.db; fi'

log "Backing up repository runtime files..."
[ -f ".env" ] && cp -f ".env" "${payload}/repo/.env"
[ -d "xray" ] && cp -a "xray" "${payload}/repo/xray"
[ -d "wireguard/conf" ] && cp -a "wireguard/conf" "${payload}/repo/wireguard-conf"
docker run --rm \
  -v proxy-vpn_caddy_data:/data \
  -v "${payload}/repo:/backup" \
  alpine:3.20 sh -lc 'mkdir -p /backup/caddy-data && cp -a /data/. /backup/caddy-data/ 2>/dev/null || true'
docker run --rm \
  -v proxy-vpn_caddy_config:/data \
  -v "${payload}/repo:/backup" \
  alpine:3.20 sh -lc 'mkdir -p /backup/caddy-config && cp -a /data/. /backup/caddy-config/ 2>/dev/null || true'

if [ "${INCLUDE_LOGS}" = "1" ] && [ -d "logs" ]; then
  mkdir -p "${payload}/repo/logs"
  for f in deploy-history.log app-release-state.json backup-status.json; do
    [ -f "logs/${f}" ] && cp -f "logs/${f}" "${payload}/repo/logs/${f}"
  done
fi

log "Backing up secret files from .env *_FILE settings..."
if [ -f ".env" ]; then
  python3 - "${payload}/meta/secrets-list.txt" <<'PY'
import os
import re
import sys
from pathlib import Path

env_path = Path(".env")
dst_path = Path(sys.argv[1])
secret_keys = ("APP_SECRET_KEY_FILE", "ADMIN_PASSWORD_FILE")
paths = []
for line in env_path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    if key in secret_keys and value:
        paths.append((key, value))
dst_path.parent.mkdir(parents=True, exist_ok=True)
with dst_path.open("w", encoding="utf-8") as f:
    for key, path in paths:
        f.write(f"{key}={path}\n")
PY
  if [ -f "${payload}/meta/secrets-list.txt" ]; then
    while IFS='=' read -r key secret_path; do
      [ -n "${secret_path}" ] || continue
      if [ -f "${secret_path}" ]; then
        mkdir -p "${payload}/secrets"
        cp -f "${secret_path}" "${payload}/secrets/${key}"
      fi
    done < "${payload}/meta/secrets-list.txt"
  fi
fi

cat > "${payload}/meta/backup-meta.txt" <<EOF
timestamp=${timestamp}
git_branch=${git_branch}
git_sha=${git_sha}
mode=${MODE}
include_logs=${INCLUDE_LOGS}
security_db_included=$([ -f "${payload}/data/security.db" ] && echo 1 || echo 0)
caddy_data_included=$([ -d "${payload}/repo/caddy-data" ] && echo 1 || echo 0)
caddy_config_included=$([ -d "${payload}/repo/caddy-config" ] && echo 1 || echo 0)
host=$(hostname)
EOF

(cd "${stage}" && tar -czf "${archive_name}" payload)
mv "${stage}/${archive_name}" "${BACKUP_DIR}/${archive_name}"
ln -sfn "${archive_name}" "${BACKUP_DIR}/latest-backup.tar.gz"
ARCHIVE_CREATED="${BACKUP_DIR}/${archive_name}"

log "Backup created: ${BACKUP_DIR}/${archive_name}"

count="${RETENTION_COUNT}"
if [ "${count}" -gt 0 ] 2>/dev/null; then
  ls -1t "${BACKUP_DIR}"/proxy-vpn-backup-*.tar.gz 2>/dev/null | awk "NR>${count}" | while read -r old; do
    rm -f "${old}"
  done
fi

log "To restore:"
log "  bash ./scripts/restore-critical.sh ${BACKUP_DIR}/${archive_name}"
log "Done."
