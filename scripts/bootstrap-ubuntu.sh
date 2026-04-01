#!/usr/bin/env bash
# Bootstrap a bare Ubuntu 24.04+ server for proxy-vpn deployment.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

wait_for_docker_daemon() {
  local attempts="${1:-30}"
  local sleep_seconds="${2:-2}"
  local i=0
  while [ "${i}" -lt "${attempts}" ]; do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep "${sleep_seconds}"
  done
  return 1
}

cleanup_stale_wireguard_run_containers() {
  local ids=""
  ids="$(docker ps -aq --filter "name=proxy-vpn-wireguard-run" 2>/dev/null || true)"
  if [ -n "${ids}" ]; then
    log "Cleaning stale one-shot wireguard containers..."
    # shellcheck disable=SC2086
    docker rm -f ${ids} >/dev/null 2>&1 || true
  fi
}

run_with_timeout() {
  local timeout_seconds="$1"
  local description="$2"
  shift 2
  if command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_seconds}" "$@"
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
      if [ "${rc}" -eq 124 ]; then
        die "${description} timed out after ${timeout_seconds}s. Check Docker/container health and rerun bootstrap."
      fi
      die "${description} failed with exit code ${rc}."
    fi
  else
    log "WARN: timeout utility not found; running without timeout guard: ${description}"
    "$@" || die "${description} failed."
  fi
}

ensure_docker_ready() {
  systemctl daemon-reload || true
  systemctl enable --now docker

  if wait_for_docker_daemon 25 2; then
    return 0
  fi

  log "Docker daemon did not become ready on first attempt, trying restart..."
  systemctl restart docker || true
  if wait_for_docker_daemon 25 2; then
    return 0
  fi

  log "--- docker service diagnostics ---"
  systemctl status --no-pager docker || true
  journalctl -u docker -n 120 --no-pager || true
  die "Cannot connect to Docker daemon after auto-recovery attempts."
}

is_interactive_shell() {
  [ -t 0 ] && [ -t 1 ]
}

prompt_value() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3:-}"
  local secret_mode="${4:-0}"
  local current_value="${!var_name:-}"
  local entered=""

  if [ "${secret_mode}" = "1" ]; then
    if [ -n "${default_value}" ]; then
      printf '%s [%s]: ' "${prompt_text}" "${default_value}"
    else
      printf '%s: ' "${prompt_text}"
    fi
    stty -echo
    IFS= read -r entered || true
    stty echo
    printf '\n'
  else
    if [ -n "${default_value}" ]; then
      printf '%s [%s]: ' "${prompt_text}" "${default_value}"
    else
      printf '%s: ' "${prompt_text}"
    fi
    IFS= read -r entered || true
  fi

  if [ -z "${entered}" ]; then
    if [ -n "${default_value}" ]; then
      printf -v "${var_name}" '%s' "${default_value}"
    else
      printf -v "${var_name}" '%s' "${current_value}"
    fi
  else
    printf -v "${var_name}" '%s' "${entered}"
  fi
}

collect_admin_inputs_if_needed() {
  if ! is_interactive_shell; then
    return 0
  fi

  log "[input] Interactive bootstrap: collecting required values..."

  VPN_PANEL_DOMAIN=""
  prompt_value VPN_PANEL_DOMAIN "Enter public panel domain (VPN_PANEL_DOMAIN)" ""
  if [ "${VPN_PANEL_DOMAIN}" = "panel.example.com" ] || [ "${VPN_PANEL_DOMAIN}" = "localhost" ]; then
    die "VPN_PANEL_DOMAIN must be a real public domain."
  fi
  [ -n "${VPN_PANEL_DOMAIN}" ] || die "VPN_PANEL_DOMAIN is required."

  if [ "${AUTO_GENERATE_VPN_CONFIGS}" = "1" ]; then
    SERVER_PUBLIC_IP=""
    prompt_value SERVER_PUBLIC_IP "Enter public server host/IP for VPN configs (SERVER_PUBLIC_IP)" ""
    if [ "${SERVER_PUBLIC_IP}" = "panel.example.com" ] || [ "${SERVER_PUBLIC_IP}" = "localhost" ]; then
      die "SERVER_PUBLIC_IP must be a real public host/IP."
    fi
    [ -n "${SERVER_PUBLIC_IP}" ] || die "SERVER_PUBLIC_IP is required when AUTO_GENERATE_VPN_CONFIGS=1."
  fi

  if [ -z "${ADMIN_EMAIL}" ] || [ "${ADMIN_EMAIL}" = "admin@example.com" ]; then
    prompt_value ADMIN_EMAIL "Enter admin email (ADMIN_EMAIL)" "admin@${VPN_PANEL_DOMAIN}"
  fi

  if [ -z "${BOOTSTRAP_ADMIN_PASSWORD}" ] || [ "${BOOTSTRAP_ADMIN_PASSWORD}" = "replace-with-strong-admin-password" ]; then
    prompt_value BOOTSTRAP_ADMIN_PASSWORD "Enter admin password (leave empty to autogenerate)" "" "1"
  fi
}

ensure_github_ssh_config() {
  install -d -m 700 /root/.ssh
  touch /root/.ssh/config
  chmod 600 /root/.ssh/config
  if ! grep -Eq "^[[:space:]]*Host[[:space:]]+${GITHUB_SSH_HOST_ALIAS}$" /root/.ssh/config; then
    cat >>/root/.ssh/config <<EOF
Host ${GITHUB_SSH_HOST_ALIAS}
  HostName github.com
  User git
  IdentityFile ${GITHUB_SSH_KEY_PATH}
  IdentitiesOnly yes
EOF
  fi
}

build_git_ssh_command() {
  printf '%s' "ssh -i ${GITHUB_SSH_KEY_PATH} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=8"
}

prepare_github_ssh_key() {
  install -d -m 700 /root/.ssh

  if [ -n "${GITHUB_DEPLOY_KEY_B64}" ]; then
    printf '%s' "${GITHUB_DEPLOY_KEY_B64}" | base64 -d > "${GITHUB_SSH_KEY_PATH}"
    chmod 600 "${GITHUB_SSH_KEY_PATH}"
  fi

  if [ ! -f "${GITHUB_SSH_KEY_PATH}" ] && [ "${GENERATE_GITHUB_SSH_KEY}" = "1" ]; then
    ssh-keygen -t ed25519 -f "${GITHUB_SSH_KEY_PATH}" -N "" -C "proxy-vpn-bootstrap@$(hostname)" >/dev/null
  fi

  [ -f "${GITHUB_SSH_KEY_PATH}" ] || die "Missing SSH key for GitHub access: ${GITHUB_SSH_KEY_PATH}"
  chmod 600 "${GITHUB_SSH_KEY_PATH}"
  if [ ! -f "${GITHUB_SSH_KEY_PATH}.pub" ]; then
    ssh-keygen -y -f "${GITHUB_SSH_KEY_PATH}" > "${GITHUB_SSH_KEY_PATH}.pub"
  fi
  chmod 644 "${GITHUB_SSH_KEY_PATH}.pub"
}

validate_repo_access() {
  local retries="${1:-20}"
  local sleep_seconds="${2:-3}"
  local i=1
  local git_ssh_cmd
  git_ssh_cmd="$(build_git_ssh_command)"

  while [ "${i}" -le "${retries}" ]; do
    if GIT_SSH_COMMAND="${git_ssh_cmd}" git ls-remote "${REPO_SSH_URL}" >/dev/null 2>&1; then
      log "GitHub repository access validated."
      return 0
    fi

    if [ "${i}" -eq 1 ]; then
      log "GitHub access is not ready yet for ${REPO_SSH_URL}."
      if [ -f "${GITHUB_SSH_KEY_PATH}.pub" ]; then
        log "Add this public key as Deploy key (read-only) in GitHub repository:"
        printf '%s\n' "----- BEGIN DEPLOY KEY (${GITHUB_SSH_KEY_PATH}.pub) -----"
        cat "${GITHUB_SSH_KEY_PATH}.pub"
        printf '%s\n' "----- END DEPLOY KEY -----"
      fi
      if is_interactive_shell; then
        log "Press Enter after key is added in GitHub to retry validation..."
        read -r _
      fi
      # One diagnostic attempt (does not fail bootstrap by itself).
      ssh -i "${GITHUB_SSH_KEY_PATH}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=8 -T git@github.com >/dev/null 2>&1 || true
    fi

    sleep "${sleep_seconds}"
    i=$((i + 1))
  done

  return 1
}

infer_github_repo_from_ssh_url() {
  # git@github.com:owner/repo.git -> owner/repo
  printf '%s' "${REPO_SSH_URL}" | sed -E 's#^git@github\.com:##; s#\.git$##'
}

ensure_public_key_in_authorized_keys() {
  local pub_key_path="$1"
  local auth_keys="/root/.ssh/authorized_keys"
  [ -f "${pub_key_path}" ] || die "Public key missing: ${pub_key_path}"
  install -d -m 700 /root/.ssh
  touch "${auth_keys}"
  chmod 600 "${auth_keys}"
  if ! grep -Fq "$(cat "${pub_key_path}")" "${auth_keys}"; then
    cat "${pub_key_path}" >> "${auth_keys}"
  fi
}

prepare_github_actions_server_key() {
  install -d -m 700 /root/.ssh
  if [ ! -f "${GITHUB_ACTIONS_SERVER_KEY_PATH}" ]; then
    ssh-keygen -t ed25519 -f "${GITHUB_ACTIONS_SERVER_KEY_PATH}" -N "" -C "proxy-vpn-actions@$(hostname)" >/dev/null
  fi
  chmod 600 "${GITHUB_ACTIONS_SERVER_KEY_PATH}"
  if [ ! -f "${GITHUB_ACTIONS_SERVER_KEY_PATH}.pub" ]; then
    ssh-keygen -y -f "${GITHUB_ACTIONS_SERVER_KEY_PATH}" > "${GITHUB_ACTIONS_SERVER_KEY_PATH}.pub"
  fi
  chmod 644 "${GITHUB_ACTIONS_SERVER_KEY_PATH}.pub"
  ensure_public_key_in_authorized_keys "${GITHUB_ACTIONS_SERVER_KEY_PATH}.pub"
}

configure_github_actions_from_server() {
  if [ "${CONFIGURE_GITHUB_ACTIONS_FROM_SERVER}" != "1" ]; then
    return 0
  fi
  if ! is_interactive_shell; then
    return 0
  fi

  prompt_value CONFIGURE_GITHUB_ACTIONS_FROM_SERVER "Configure GitHub Actions vars/secrets from this server now? (1/0)" "1"
  if [ "${CONFIGURE_GITHUB_ACTIONS_FROM_SERVER}" != "1" ]; then
    return 0
  fi

  if [ -z "${GITHUB_ACTIONS_REPO}" ]; then
    GITHUB_ACTIONS_REPO="$(infer_github_repo_from_ssh_url)"
  fi
  prompt_value GITHUB_ACTIONS_REPO "GitHub repository (owner/repo) for Actions config" "${GITHUB_ACTIONS_REPO}"
  [ -n "${GITHUB_ACTIONS_REPO}" ] || die "GITHUB_ACTIONS_REPO is required for Actions config."

  if [ -z "${SERVER_PUBLIC_IP}" ]; then
    prompt_value SERVER_PUBLIC_IP "Server host/IP for GitHub Actions SSH connection (SSH_HOST)" ""
  fi
  [ -n "${SERVER_PUBLIC_IP}" ] || die "SERVER_PUBLIC_IP is required for Actions config."

  if [ -z "${GITHUB_ACTIONS_TOKEN}" ]; then
    prompt_value GITHUB_ACTIONS_TOKEN "GitHub token with repo/actions permissions" "" "1"
  fi
  [ -n "${GITHUB_ACTIONS_TOKEN}" ] || die "GITHUB_ACTIONS_TOKEN is required for Actions config."

  if ! command -v gh >/dev/null 2>&1; then
    log "Installing GitHub CLI (gh)..."
    apt-get install -y gh
  fi

  if ! gh auth status >/dev/null 2>&1; then
    printf '%s' "${GITHUB_ACTIONS_TOKEN}" | gh auth login --hostname github.com --with-token >/dev/null
  fi

  prepare_github_actions_server_key

  prompt_value GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD "Also store SSH_PASSWORD secret in GitHub? (1/0)" "${GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD}"
  if [ "${GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD}" = "1" ] && [ -z "${SERVER_ROOT_PASSWORD_FOR_GITHUB}" ]; then
    prompt_value SERVER_ROOT_PASSWORD_FOR_GITHUB "Enter server root password for GitHub secret SSH_PASSWORD" "" "1"
  fi

  log "Configuring GitHub Actions variables/secrets in ${GITHUB_ACTIONS_REPO}..."
  REPO="${GITHUB_ACTIONS_REPO}" \
  SSH_HOST="${SERVER_PUBLIC_IP}" \
  SSH_USER="root" \
  SSH_PASSWORD="${SERVER_ROOT_PASSWORD_FOR_GITHUB}" \
  DEPLOY_PATH="${DEPLOY_PATH}" \
  VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN}" \
  ADMIN_USERNAME="${ADMIN_USERNAME}" \
  ADMIN_EMAIL="${ADMIN_EMAIL}" \
  APP_SECRET_KEY_FILE="${APP_SECRET_KEY_FILE}" \
  ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE}" \
  RENDER_ENV_FROM_CI="0" \
  DEPLOY_SSH_KEY_PATH="${GITHUB_ACTIONS_SERVER_KEY_PATH}" \
  bash "${DEPLOY_PATH}/scripts/setup-github-config.sh"
}

if [ "${EUID}" -ne 0 ]; then
  die "Run as root (or with sudo)."
fi

TARGET_USER="${TARGET_USER:-root}"
REPO_SSH_URL="${REPO_SSH_URL:-git@github.com:SolonnikovDV/proxy_vpn.git}"
DEPLOY_PATH="${DEPLOY_PATH:-/opt/proxy_vpn}"
RUN_DOCKER_HELLO="${RUN_DOCKER_HELLO:-1}"
CLONE_REPO="${CLONE_REPO:-1}"
AUTO_PULL_REPO="${AUTO_PULL_REPO:-1}"
CONFIGURE_GITHUB_REPO_ACCESS="${CONFIGURE_GITHUB_REPO_ACCESS:-1}"
AUTO_GENERATE_VPN_CONFIGS="${AUTO_GENERATE_VPN_CONFIGS:-1}"
FORCE_REGENERATE_VPN_CONFIGS="${FORCE_REGENERATE_VPN_CONFIGS:-0}"
WRITE_APP_ENV="${WRITE_APP_ENV:-1}"
ENABLE_UFW="${ENABLE_UFW:-1}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-1}"
SSH_PORT="${SSH_PORT:-22}"
SECRETS_DIR="${SECRETS_DIR:-/etc/proxy-vpn/secrets}"
APP_SECRET_KEY_FILE="${APP_SECRET_KEY_FILE:-${SECRETS_DIR}/app_secret_key}"
ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE:-${SECRETS_DIR}/admin_password}"
FORCE_ROTATE_SECRETS="${FORCE_ROTATE_SECRETS:-0}"
GITHUB_SSH_KEY_PATH="${GITHUB_SSH_KEY_PATH:-/root/.ssh/id_ed25519_proxy_vpn_github}"
GITHUB_SSH_HOST_ALIAS="${GITHUB_SSH_HOST_ALIAS:-github.com}"
GENERATE_GITHUB_SSH_KEY="${GENERATE_GITHUB_SSH_KEY:-1}"
GITHUB_DEPLOY_KEY_B64="${GITHUB_DEPLOY_KEY_B64:-}"
GITHUB_VALIDATE_RETRIES="${GITHUB_VALIDATE_RETRIES:-20}"
GITHUB_VALIDATE_SLEEP_SECONDS="${GITHUB_VALIDATE_SLEEP_SECONDS:-3}"
CONFIGURE_GITHUB_ACTIONS_FROM_SERVER="${CONFIGURE_GITHUB_ACTIONS_FROM_SERVER:-1}"
GITHUB_ACTIONS_REPO="${GITHUB_ACTIONS_REPO:-}"
GITHUB_ACTIONS_TOKEN="${GITHUB_ACTIONS_TOKEN:-}"
GITHUB_ACTIONS_SERVER_KEY_PATH="${GITHUB_ACTIONS_SERVER_KEY_PATH:-/root/.ssh/id_ed25519_proxy_vpn_actions}"
GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD="${GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD:-0}"
SERVER_ROOT_PASSWORD_FOR_GITHUB="${SERVER_ROOT_PASSWORD_FOR_GITHUB:-}"

VPN_PANEL_DOMAIN="${VPN_PANEL_DOMAIN:-panel.example.com}"
SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-}"
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
collect_admin_inputs_if_needed

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
ensure_docker_ready

log "[3/12] Install Git + OpenSSH client/server..."
apt-get install -y git openssh-client openssh-server
if ! systemctl enable --now ssh >/dev/null 2>&1 && ! systemctl enable --now sshd >/dev/null 2>&1; then
  die "OpenSSH service unit not found (ssh/sshd)."
fi

log "[4/12] Validate docker/compose..."
docker --version
docker compose version
docker info >/dev/null

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
if [ "${CLONE_REPO}" = "1" ] && [ "${CONFIGURE_GITHUB_REPO_ACCESS}" = "1" ]; then
  log "[9.1/12] Configure GitHub SSH access for repository clone..."
  prepare_github_ssh_key
  ensure_github_ssh_config
  if ! validate_repo_access "${GITHUB_VALIDATE_RETRIES}" "${GITHUB_VALIDATE_SLEEP_SECONDS}"; then
    die "Unable to validate access to ${REPO_SSH_URL}. Add deploy key in GitHub and rerun bootstrap."
  fi
fi
if [ "${CLONE_REPO}" = "1" ]; then
  if [ ! -d "${DEPLOY_PATH}/.git" ]; then
    rm -rf "${DEPLOY_PATH}"
    git_ssh_cmd="$(build_git_ssh_command)"
    su - "${TARGET_USER}" -c "GIT_SSH_COMMAND='${git_ssh_cmd}' git clone '${REPO_SSH_URL}' '${DEPLOY_PATH}'"
  else
    log "Repository already exists at ${DEPLOY_PATH}, skipping clone."
    if [ "${AUTO_PULL_REPO}" = "1" ]; then
      if [ -n "$(su - "${TARGET_USER}" -c "cd '${DEPLOY_PATH}' && git status --porcelain" 2>/dev/null)" ]; then
        die "Repository has local changes at ${DEPLOY_PATH}. Commit/stash/reset and rerun bootstrap."
      fi
      git_ssh_cmd="$(build_git_ssh_command)"
      su - "${TARGET_USER}" -c "cd '${DEPLOY_PATH}' && b=\$(git rev-parse --abbrev-ref HEAD) && GIT_SSH_COMMAND='${git_ssh_cmd}' git fetch origin \"\$b\" && GIT_SSH_COMMAND='${git_ssh_cmd}' git pull --ff-only origin \"\$b\""
      log "Repository updated to latest remote revision."
    fi
  fi
else
  install -d -m 0755 "${DEPLOY_PATH}"
  log "CLONE_REPO=0, repository clone skipped."
fi
chown -R "${TARGET_USER}:${TARGET_USER}" "${DEPLOY_PATH}"

if [ "${AUTO_GENERATE_VPN_CONFIGS}" = "1" ]; then
  log "[9.2/12] Auto-generate VPN configs (WireGuard + Xray REALITY)..."
  if [ -z "${SERVER_PUBLIC_IP}" ]; then
    if [ "${VPN_PANEL_DOMAIN}" != "panel.example.com" ] && [ "${VPN_PANEL_DOMAIN}" != "localhost" ]; then
      SERVER_PUBLIC_IP="${VPN_PANEL_DOMAIN}"
    else
      die "Set SERVER_PUBLIC_IP (or real VPN_PANEL_DOMAIN) for automatic VPN config generation."
    fi
  fi

  WG_SERVER_CONF_PATH="${DEPLOY_PATH}/wireguard/conf/wg0.conf"
  XRAY_CONFIG_PATH_ABS="${DEPLOY_PATH}/xray/config.json"

  if [ "${FORCE_REGENERATE_VPN_CONFIGS}" = "1" ]; then
    rm -f "${WG_SERVER_CONF_PATH}" "${DEPLOY_PATH}/wireguard/conf/client1.conf" \
      "${XRAY_CONFIG_PATH_ABS}" "${DEPLOY_PATH}/xray/client-connection.txt"
  fi

  cleanup_stale_wireguard_run_containers

  if [ ! -f "${WG_SERVER_CONF_PATH}" ]; then
    run_with_timeout 180 "WireGuard config generation" \
      su - "${TARGET_USER}" -c "cd '${DEPLOY_PATH}' && SERVER_PUBLIC_IP='${SERVER_PUBLIC_IP}' WG_PORT='${WG_PORT}' bash ./scripts/setup-wireguard.sh"
  else
    log "WireGuard config exists, skip generation: ${WG_SERVER_CONF_PATH}"
  fi

  if [ ! -f "${XRAY_CONFIG_PATH_ABS}" ]; then
    run_with_timeout 180 "Xray REALITY config generation" \
      su - "${TARGET_USER}" -c "cd '${DEPLOY_PATH}' && SERVER_PUBLIC_IP='${SERVER_PUBLIC_IP}' XRAY_PORT='${XRAY_PORT}' bash ./scripts/setup-xray-reality.sh"
  else
    log "Xray config exists, skip generation: ${XRAY_CONFIG_PATH_ABS}"
  fi
fi

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

log "[10.5/12] Optional GitHub Actions configuration from server..."
configure_github_actions_from_server

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
log "     - key path: ${GITHUB_SSH_KEY_PATH} (pub: ${GITHUB_SSH_KEY_PATH}.pub)"
log "     - use GITHUB_DEPLOY_KEY_B64 to pre-seed private key non-interactively"
log "  3) Check ${DEPLOY_PATH}/.env and secret files in ${SECRETS_DIR}"
log "  4) cd ${DEPLOY_PATH}"
log "  5) bash ./scripts/run.sh prod up"
