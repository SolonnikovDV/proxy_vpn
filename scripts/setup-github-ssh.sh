#!/usr/bin/env bash
# Setup SSH key for GitHub access on server.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

TARGET_USER="${TARGET_USER:-root}"
KEY_PATH="${KEY_PATH:-$HOME/.ssh/id_ed25519_github}"
KEY_COMMENT="${KEY_COMMENT:-proxy-vpn-deploy}"

command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen not found"
command -v ssh >/dev/null 2>&1 || die "ssh client not found"

if [ ! -d "$(dirname "${KEY_PATH}")" ]; then
  mkdir -p "$(dirname "${KEY_PATH}")"
fi
chmod 700 "$(dirname "${KEY_PATH}")"

if [ ! -f "${KEY_PATH}" ]; then
  log "[1/4] Generating SSH key: ${KEY_PATH}"
  ssh-keygen -t ed25519 -a 64 -C "${KEY_COMMENT}" -f "${KEY_PATH}" -N ""
else
  log "[1/4] SSH key already exists: ${KEY_PATH}"
fi

log "[2/4] Ensuring GitHub host key in known_hosts"
touch "$HOME/.ssh/known_hosts"
chmod 600 "$HOME/.ssh/known_hosts"
if ! ssh-keygen -F github.com >/dev/null 2>&1; then
  ssh-keyscan -t rsa,ecdsa,ed25519 github.com >> "$HOME/.ssh/known_hosts" 2>/dev/null || true
fi

log "[3/4] Public key (add as Deploy key in GitHub repository):"
printf '\n'
cat "${KEY_PATH}.pub"
printf '\n\n'

log "[4/4] Optional connectivity test (requires key added in GitHub):"
log "  GIT_SSH_COMMAND='ssh -i ${KEY_PATH} -o IdentitiesOnly=yes' ssh -T git@github.com"
log "  GIT_SSH_COMMAND='ssh -i ${KEY_PATH} -o IdentitiesOnly=yes' git ls-remote git@github.com:SolonnikovDV/proxy_vpn.git"
log ""
log "Tip: put this in shell profile for deploy user:"
log "  export GIT_SSH_COMMAND='ssh -i ${KEY_PATH} -o IdentitiesOnly=yes'"
