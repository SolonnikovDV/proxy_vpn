#!/usr/bin/env bash
# Install systemd timer for periodic critical backup snapshots.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if [ "${EUID}" -ne 0 ]; then
  die "Run as root (or with sudo)."
fi

DEPLOY_PATH="${DEPLOY_PATH:-/opt/proxy_vpn}"
RUN_USER="${RUN_USER:-root}"
ON_CALENDAR="${ON_CALENDAR:-daily}"
BACKUP_DIR="${BACKUP_DIR:-${DEPLOY_PATH}/backups}"
RETENTION_COUNT="${RETENTION_COUNT:-14}"
MODE="${MODE:-prod}"
CHECK_INTEGRITY="${CHECK_INTEGRITY:-1}"

[ -d "${DEPLOY_PATH}" ] || die "DEPLOY_PATH does not exist: ${DEPLOY_PATH}"
id "${RUN_USER}" >/dev/null 2>&1 || die "RUN_USER does not exist: ${RUN_USER}"

SERVICE_PATH="/etc/systemd/system/proxy-vpn-backup.service"
TIMER_PATH="/etc/systemd/system/proxy-vpn-backup.timer"

log "[1/4] Writing backup service unit"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=proxy-vpn critical backup snapshot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
User=${RUN_USER}
WorkingDirectory=${DEPLOY_PATH}
Environment=BACKUP_DIR=${BACKUP_DIR}
Environment=RETENTION_COUNT=${RETENTION_COUNT}
Environment=MODE=${MODE}
Environment=CHECK_INTEGRITY=${CHECK_INTEGRITY}
ExecStart=/usr/bin/env bash ${DEPLOY_PATH}/scripts/backup-critical.sh
EOF

log "[2/4] Writing backup timer unit"
cat > "${TIMER_PATH}" <<EOF
[Unit]
Description=Run proxy-vpn backup on schedule

[Timer]
OnCalendar=${ON_CALENDAR}
Persistent=true
Unit=proxy-vpn-backup.service

[Install]
WantedBy=timers.target
EOF

log "[3/4] Reloading systemd and enabling timer"
systemctl daemon-reload
systemctl enable --now proxy-vpn-backup.timer

log "[4/4] Status"
systemctl status --no-pager proxy-vpn-backup.timer || true
log ""
log "Manual run:"
log "  systemctl start proxy-vpn-backup.service"
log "Logs:"
log "  journalctl -u proxy-vpn-backup.service -n 100 --no-pager"
