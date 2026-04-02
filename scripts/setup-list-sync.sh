#!/usr/bin/env bash
# Install systemd timer for periodic whitelist/blacklist feed sync.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if [ "${EUID}" -ne 0 ]; then
  die "Run as root (or with sudo)."
fi

DEPLOY_PATH="${DEPLOY_PATH:-/opt/proxy_vpn}"
RUN_USER="${RUN_USER:-root}"
ON_CALENDAR="${ON_CALENDAR:-*:0/30}"

[ -d "${DEPLOY_PATH}" ] || die "DEPLOY_PATH does not exist: ${DEPLOY_PATH}"
id "${RUN_USER}" >/dev/null 2>&1 || die "RUN_USER does not exist: ${RUN_USER}"

SERVICE_PATH="/etc/systemd/system/proxy-vpn-list-sync.service"
TIMER_PATH="/etc/systemd/system/proxy-vpn-list-sync.timer"

log "[1/4] Writing list-sync service unit"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=proxy-vpn resource list sync (whitelist/blacklist)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${RUN_USER}
WorkingDirectory=${DEPLOY_PATH}
EnvironmentFile=-${DEPLOY_PATH}/.env
ExecStart=/usr/bin/env bash ${DEPLOY_PATH}/scripts/sync-resource-lists.sh
EOF

log "[2/4] Writing list-sync timer unit"
cat > "${TIMER_PATH}" <<EOF
[Unit]
Description=Run proxy-vpn list sync on schedule

[Timer]
OnCalendar=${ON_CALENDAR}
Persistent=true
Unit=proxy-vpn-list-sync.service

[Install]
WantedBy=timers.target
EOF

log "[3/4] Reloading systemd and enabling timer"
systemctl daemon-reload
systemctl enable --now proxy-vpn-list-sync.timer

log "[4/4] Status"
systemctl status --no-pager proxy-vpn-list-sync.timer || true
log ""
log "Manual run:"
log "  systemctl start proxy-vpn-list-sync.service"
log "Logs:"
log "  journalctl -u proxy-vpn-list-sync.service -n 100 --no-pager"

