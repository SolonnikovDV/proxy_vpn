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

command -v apt-get >/dev/null 2>&1 || die "This script supports Debian/Ubuntu only."

log "[1/8] System update..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release

log "[2/8] Install Docker Engine + Compose plugin..."
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

log "[3/8] Install Git + OpenSSH client/server..."
apt-get install -y git openssh-client openssh-server
if ! systemctl enable --now ssh >/dev/null 2>&1 && ! systemctl enable --now sshd >/dev/null 2>&1; then
  die "OpenSSH service unit not found (ssh/sshd)."
fi

log "[4/8] Validate docker/compose..."
docker --version
docker compose version

if [ "${RUN_DOCKER_HELLO}" = "1" ]; then
  log "[5/8] Docker hello-world check..."
  docker run --rm hello-world >/dev/null
fi

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  die "TARGET_USER does not exist: ${TARGET_USER}"
fi

log "[6/8] Prepare deploy directory..."
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

log "[7/8] Validate SSH service..."
if systemctl is-active --quiet ssh; then
  log "SSH service is active: ssh"
elif systemctl is-active --quiet sshd; then
  log "SSH service is active: sshd"
else
  die "SSH service is not active."
fi

log "[8/8] Result summary"
log "Bootstrap complete."
log "Repository: ${DEPLOY_PATH}"
log "Next steps:"
log "  1) Ensure server access key is in ~/.ssh/authorized_keys for ${TARGET_USER}"
log "  2) Ensure SSH deploy key for ${REPO_SSH_URL} is configured on server (if CLONE_REPO=1)"
log "  3) cd ${DEPLOY_PATH}"
log "  4) bash ./scripts/run.sh prod up"
