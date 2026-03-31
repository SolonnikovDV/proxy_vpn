#!/usr/bin/env bash
# Bootstrap a bare Ubuntu 24.04+ server for proxy-vpn deployment.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if [ "${EUID}" -ne 0 ]; then
  die "Run as root (or with sudo)."
fi

TARGET_USER="${TARGET_USER:-root}"
REPO_SSH_URL="${REPO_SSH_URL:-git@github.com:SolonnikovDV/proxy_vpn.git}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/proxy_vpn}"
RUN_DOCKER_HELLO="${RUN_DOCKER_HELLO:-1}"
CLONE_REPO="${CLONE_REPO:-1}"
WRITE_APP_ENV="${WRITE_APP_ENV:-1}"
ENABLE_UFW="${ENABLE_UFW:-1}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-1}"
SSH_PORT="${SSH_PORT:-22}"
SECRETS_DIR="${SECRETS_DIR:-/etc/proxy-vpn/secrets}"
APP_SECRET_KEY_FILE="${APP_SECRET_KEY_FILE:-${SECRETS_DIR}/app_secret_key}"
ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE:-${SECRETS_DIR}/admin_password}"
FORCE_ROTATE_SECRETS="${FORCE_ROTATE_SECRETS:-0}"

VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-panel.example.com}"
CADDYFILE_PATH="${CADDYFILE_PATH:-Caddyfile.prod}"
CADDY_HTTP_PORT="${CADDY_HTTP_PORT:-80}"
CADDY_HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
XRAY_PORT="${XRAY_PORT:-8443}"
WG_PORT="${WG_PORT:-51820}"
CAPACITY_TARGET_ACTIVE_USERS="${CAPACITY_TARGET_ACTIVE_USERS:-15}"
CAPACITY_CPU_WARN_P95="${CAPACITY_CPU_WARN_P95:-70}"
CAPACITY_CPU_CRIT_P95="${CAPACITY_CPU_CRIT_P95:-80}"
CAPACITY_RAM_WARN_P95="${CAPACITY_RAM_WARN_P95:-80}"
CAPACITY_RAM_CRIT_P95="${CAPACITY_RAM_CRIT_P95:-85}"
CAPACITY_DISK_WARN_P95="${CAPACITY_DISK_WARN_P95:-85}"
CAPACITY_DISK_CRIT_P95="${CAPACITY_DISK_CRIT_P95:-92}"
DASHBOARD_REFRESH_SECONDS="${DASHBOARD_REFRESH_SECONDS:-30}"
LOGIN_MAX_ATTEMPTS="${LOGIN_MAX_ATTEMPTS:-5}"
LOGIN_WINDOW_MINUTES="${LOGIN_WINDOW_MINUTES:-10}"
LOGIN_LOCK_MINUTES="${LOGIN_LOCK_MINUTES:-15}"
SECURITY_GEOIP_ENABLED="${SECURITY_GEOIP_ENABLED:-1}"
SECURITY_GEOIP_TIMEOUT_SECONDS="${SECURITY_GEOIP_TIMEOUT_SECONDS:-1.5}"
SECURITY_DEFAULT_BLOCK_SECONDS="${SECURITY_DEFAULT_BLOCK_SECONDS:-900}"
SECURITY_HTTP_WINDOW_SECONDS="${SECURITY_HTTP_WINDOW_SECONDS:-10}"
SECURITY_HTTP_MAX_REQUESTS="${SECURITY_HTTP_MAX_REQUESTS:-120}"
SECURITY_PROBE_PATH_THRESHOLD="${SECURITY_PROBE_PATH_THRESHOLD:-12}"
SECURITY_BLOCK_SECONDS_DDOS="${SECURITY_BLOCK_SECONDS_DDOS:-600}"
SECURITY_BLOCK_SECONDS_BRUTE="${SECURITY_BLOCK_SECONDS_BRUTE:-900}"
SECURITY_SERVER_CHECK_INTERVAL_SECONDS="${SECURITY_SERVER_CHECK_INTERVAL_SECONDS:-60}"
SECURITY_SERVER_EVENT_COOLDOWN_SECONDS="${SECURITY_SERVER_EVENT_COOLDOWN_SECONDS:-300}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
BOOTSTRAP_ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-}"
PRINT_GENERATED_ADMIN_PASSWORD="${PRINT_GENERATED_ADMIN_PASSWORD:-0}"
GENERATED_ADMIN_PASSWORD_REPORT_PATH="${GENERATED_ADMIN_PASSWORD_REPORT_PATH:-/root/proxy-vpn-bootstrap-admin-password.txt}"

command -v apt-get >/dev/null 2>&1 || die "This script supports Debian/Ubuntu only."

log "[1/12] System update..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release openssl

log "[2/12] Install Docker Engine + Compose plugin..."
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable
EOF

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

log "[3/12] Install Git + OpenSSH client/server..."
apt-get install -y git openssh-client openssh-server
if ! systemctl enable --now ssh >/dev/null 2>&1 && ! systemctl enable --now sshd >/dev/null 2>&1; then
  die "OpenSSH service unit not found (ssh/sshd)."
fi

log "[4/12] Validate docker/compose..."
docker --version
docker compose version

if [ "${RUN_DOCKER_HELLO}" = "1" ]; then
  log "[5/12] Docker hello-world check..."
  docker run --rm hello-world >/dev/null
fi

if [ "${ENABLE_UNATTENDED_UPGRADES}" = "1" ]; then
  log "[6/12] Configure unattended-upgrades..."
  apt-get install -y unattended-upgrades apt-listchanges
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
fi

if [ "${ENABLE_UFW}" = "1" ]; then
  log "[7/12] Configure UFW firewall..."
  apt-get install -y ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"
  ufw allow "${CADDY_HTTP_PORT}/tcp"
  ufw allow "${CADDY_HTTPS_PORT}/tcp"
  ufw allow "${XRAY_PORT}/tcp"
  ufw allow "${WG_PORT}/udp"
  ufw --force enable
  ufw status verbose || true
fi

if [ "${ENABLE_FAIL2BAN}" = "1" ]; then
  log "[8/12] Configure fail2ban..."
  apt-get install -y fail2ban
  cat >/etc/fail2ban/jail.d/proxy-vpn.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
findtime = 10m
maxretry = 5
bantime = 30m

[sshd-ddos]
enabled = true
port = ${SSH_PORT}
backend = systemd
findtime = 10m
maxretry = 6
bantime = 1h
EOF
  systemctl enable --now fail2ban
  fail2ban-client status sshd || true
fi

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  die "TARGET_USER does not exist: ${TARGET_USER}"
fi

log "[9/12] Prepare deploy directory..."
install -d -m 0755 "$(dirname "${DEPLOY_PATH}")"
if [ "${CLONE_REPO}" = "1" ]; then
  if [ ! -d "${DEPLOY_PATH}/.git" ]; then
    rm -rf "${DEPLOY_PATH}"
    su - "${TARGET_USER}" -c "git clone '${REPO_SSH_URL}' '${DEPLOY_PATH}'"
  else
    log "Repository already exists at ${DEPLOY_PATH}, skipping clone."
  fi
else
  install -d -m 0755 "${DEPLOY_PATH}"
  log "CLONE_REPO=0, repository clone skipped."
fi
chown -R "${TARGET_USER}:${TARGET_USER}" "${DEPLOY_PATH}"

ensure_secret_file() {
  local path="$1"
  local value="${2:-}"
  local gen="${3:-0}"
  local created_var="${4:-}"

  if [ "${FORCE_ROTATE_SECRETS}" = "1" ]; then
    rm -f "${path}"
  fi

  if [ -f "${path}" ]; then
    chmod 600 "${path}"
    chown root:root "${path}"
    if [ -n "${created_var}" ]; then
      printf -v "${created_var}" '%s' "0"
    fi
    return 0
  fi

  install -d -m 700 "$(dirname "${path}")"
  if [ -n "${value}" ]; then
    printf '%s' "${value}" > "${path}"
  elif [ "${gen}" = "1" ]; then
    openssl rand -base64 48 | tr -d '\n' > "${path}"
  else
    die "Cannot create secret file ${path}: no value provided."
  fi
  chmod 600 "${path}"
  chown root:root "${path}"
  if [ -n "${created_var}" ]; then
    printf -v "${created_var}" '%s' "1"
  fi
}

if [ "${WRITE_APP_ENV}" = "1" ]; then
  log "[10/12] Prepare secret files and render .env ..."
  app_secret_created="0"
  admin_secret_created="0"
  ensure_secret_file "${APP_SECRET_KEY_FILE}" "" "1" app_secret_created
  ensure_secret_file "${ADMIN_PASSWORD_FILE}" "${BOOTSTRAP_ADMIN_PASSWORD}" "1" admin_secret_created
  cat > "${DEPLOY_PATH}/.env" <<EOF
CADDYFILE_PATH=${CADDYFILE_PATH}
VPN_PANEL_DOMAIN=${VPN_PANEL_DOMAIN}
CADDY_HTTP_PORT=${CADDY_HTTP_PORT}
CADDY_HTTPS_PORT=${CADDY_HTTPS_PORT}
XRAY_PORT=${XRAY_PORT}
WG_PORT=${WG_PORT}
CAPACITY_TARGET_ACTIVE_USERS=${CAPACITY_TARGET_ACTIVE_USERS}
CAPACITY_CPU_WARN_P95=${CAPACITY_CPU_WARN_P95}
CAPACITY_CPU_CRIT_P95=${CAPACITY_CPU_CRIT_P95}
CAPACITY_RAM_WARN_P95=${CAPACITY_RAM_WARN_P95}
CAPACITY_RAM_CRIT_P95=${CAPACITY_RAM_CRIT_P95}
CAPACITY_DISK_WARN_P95=${CAPACITY_DISK_WARN_P95}
CAPACITY_DISK_CRIT_P95=${CAPACITY_DISK_CRIT_P95}
DASHBOARD_REFRESH_SECONDS=${DASHBOARD_REFRESH_SECONDS}
LOGIN_MAX_ATTEMPTS=${LOGIN_MAX_ATTEMPTS}
LOGIN_WINDOW_MINUTES=${LOGIN_WINDOW_MINUTES}
LOGIN_LOCK_MINUTES=${LOGIN_LOCK_MINUTES}
SECURITY_GEOIP_ENABLED=${SECURITY_GEOIP_ENABLED}
SECURITY_GEOIP_TIMEOUT_SECONDS=${SECURITY_GEOIP_TIMEOUT_SECONDS}
SECURITY_DEFAULT_BLOCK_SECONDS=${SECURITY_DEFAULT_BLOCK_SECONDS}
SECURITY_HTTP_WINDOW_SECONDS=${SECURITY_HTTP_WINDOW_SECONDS}
SECURITY_HTTP_MAX_REQUESTS=${SECURITY_HTTP_MAX_REQUESTS}
SECURITY_PROBE_PATH_THRESHOLD=${SECURITY_PROBE_PATH_THRESHOLD}
SECURITY_BLOCK_SECONDS_DDOS=${SECURITY_BLOCK_SECONDS_DDOS}
SECURITY_BLOCK_SECONDS_BRUTE=${SECURITY_BLOCK_SECONDS_BRUTE}
SECURITY_SERVER_CHECK_INTERVAL_SECONDS=${SECURITY_SERVER_CHECK_INTERVAL_SECONDS}
SECURITY_SERVER_EVENT_COOLDOWN_SECONDS=${SECURITY_SERVER_EVENT_COOLDOWN_SECONDS}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_EMAIL=${ADMIN_EMAIL}
APP_SECRET_KEY_FILE=${APP_SECRET_KEY_FILE}
ADMIN_PASSWORD_FILE=${ADMIN_PASSWORD_FILE}
EOF
  chmod 600 "${DEPLOY_PATH}/.env"
  chown "${TARGET_USER}:${TARGET_USER}" "${DEPLOY_PATH}/.env"

  if [ "${PRINT_GENERATED_ADMIN_PASSWORD}" = "1" ] && [ "${admin_secret_created}" = "1" ] && [ -z "${BOOTSTRAP_ADMIN_PASSWORD}" ]; then
    generated_admin_password="$(tr -d '\r\n' < "${ADMIN_PASSWORD_FILE}")"
    printf '%s\n' "${generated_admin_password}" > "${GENERATED_ADMIN_PASSWORD_REPORT_PATH}"
    chmod 600 "${GENERATED_ADMIN_PASSWORD_REPORT_PATH}"
    chown root:root "${GENERATED_ADMIN_PASSWORD_REPORT_PATH}"
    log "Generated admin password report: ${GENERATED_ADMIN_PASSWORD_REPORT_PATH}"
  fi
else
  log "[10/12] WRITE_APP_ENV=0, skip .env and secret file provisioning."
fi

log "[11/12] Validate SSH service..."
if systemctl is-active --quiet ssh; then
  log "SSH service is active: ssh"
elif systemctl is-active --quiet sshd; then
  log "SSH service is active: sshd"
else
  die "SSH service is not active."
fi

log "[12/12] Result summary"
log "Bootstrap complete."
log "Repository: ${DEPLOY_PATH}"
log "Next steps:"
log "  1) Ensure server access key is in ~/.ssh/authorized_keys for ${TARGET_USER}"
log "  2) Ensure SSH deploy key for ${REPO_SSH_URL} is configured on server (if CLONE_REPO=1)"
log "  3) Check ${DEPLOY_PATH}/.env and secret files in ${SECRETS_DIR}"
log "  4) cd ${DEPLOY_PATH}"
log "  5) bash ./scripts/run.sh prod up"
