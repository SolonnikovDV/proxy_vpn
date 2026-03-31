#!/usr/bin/env bash
# Install systemd timer for scheduled auto-update/rebuild.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if [ "${EUID}" -ne 0 ]; then
  die "Run as root (or with sudo)."
fi

DEPLOY_PATH="${DEPLOY_PATH:-/opt/proxy_vpn}"
RUN_USER="${RUN_USER:-root}"
BRANCH="${BRANCH:-main}"
MODE="${MODE:-prod}"
ON_CALENDAR="${ON_CALENDAR:-*:0/15}"

[ -d "${DEPLOY_PATH}" ] || die "DEPLOY_PATH does not exist: ${DEPLOY_PATH}"
id "${RUN_USER}" >/dev/null 2>&1 || die "RUN_USER does not exist: ${RUN_USER}"

SERVICE_PATH="/etc/systemd/system/proxy-vpn-auto-update.service"
TIMER_PATH="/etc/systemd/system/proxy-vpn-auto-update.timer"

log "[1/4] Writing service unit"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=proxy-vpn auto update and rebuild
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
User=${RUN_USER}
WorkingDirectory=${DEPLOY_PATH}
Environment=BRANCH=${BRANCH}
Environment=MODE=${MODE}
ExecStart=/usr/bin/env bash ${DEPLOY_PATH}/scripts/auto-update.sh
EOF

log "[2/4] Writing timer unit"
cat > "${TIMER_PATH}" <<EOF
[Unit]
Description=Run proxy-vpn auto update on schedule

[Timer]
OnCalendar=${ON_CALENDAR}
Persistent=true
Unit=proxy-vpn-auto-update.service

[Install]
WantedBy=timers.target
EOF

log "[3/4] Reloading systemd and enabling timer"
systemctl daemon-reload
systemctl enable --now proxy-vpn-auto-update.timer

log "[4/4] Status"
systemctl status --no-pager proxy-vpn-auto-update.timer || true
log ""
log "Manual run:"
log "  systemctl start proxy-vpn-auto-update.service"
log "Logs:"
log "  journalctl -u proxy-vpn-auto-update.service -n 100 --no-pager"
