#!/usr/bin/env bash
# Manual runbook for fresh Ubuntu server setup and production start.
# Execute commands step-by-step. Replace placeholders before running.

set -euo pipefail

cat <<'EOF'
=========================
proxy-vpn server runbook
=========================

0) Connect to server (run on local machine):
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes root@v734690.hosted-by-vdsina.com

1) Prepare bare Ubuntu (run on server):
apt-get update -y && apt-get install -y curl git
curl -fsSL https://raw.githubusercontent.com/SolonnikovDV/proxy_vpn/main/scripts/bootstrap-ubuntu.sh -o /root/bootstrap-ubuntu.sh
chmod +x /root/bootstrap-ubuntu.sh
TARGET_USER=root DEPLOY_PATH=/opt/proxy_vpn CLONE_REPO=0 /root/bootstrap-ubuntu.sh

2) Clone project (run on server):
test -d /opt/proxy_vpn/.git || git clone https://github.com/SolonnikovDV/proxy_vpn.git /opt/proxy_vpn
cd /opt/proxy_vpn

3) Prepare production env (run on server):
cp -n .env.prod.example .env
# edit manually and set real values:
# - VPN_PANEL_DOMAIN=vpn.example.com
# - ADMIN_EMAIL=admin@example.com
# - APP_SECRET_KEY=<strong-random>
# - ADMIN_PASSWORD=<strong-password>

4) Generate WireGuard + Xray configs (run on server):
SERVER_PUBLIC_IP="v734690.hosted-by-vdsina.com" bash ./scripts/setup-wireguard.sh
SERVER_PUBLIC_IP="v734690.hosted-by-vdsina.com" XRAY_PORT=8443 bash ./scripts/setup-xray-reality.sh

5) Preflight (run on server):
bash ./scripts/preflight-prod.sh

6) Start production stack (run on server):
bash ./scripts/run.sh prod up

7) Validate health (run on server):
bash ./scripts/run.sh prod ps
curl -fsS http://127.0.0.1:80/health

8) Enable scheduled auto-update (run on server):
DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" \
  bash ./scripts/setup-auto-update.sh
systemctl status --no-pager proxy-vpn-auto-update.timer

9) Prepare private key for GitHub Actions secret DEPLOY_SSH_KEY (run on server):
test -f /root/.ssh/id_ed25519 || ssh-keygen -t ed25519 -a 64 -N "" -f /root/.ssh/id_ed25519 -C "proxy-vpn-actions"
cat /root/.ssh/id_ed25519

10) Ensure login key is in authorized_keys (run on server):
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# replace placeholder with your real public key:
echo "ssh-ed25519 AAAA...YOUR_PUBLIC_KEY..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
systemctl restart ssh || systemctl restart sshd

11) Configure GitHub Variables/Secrets for CI (run on local machine with gh auth):
# Variables (compatible with old gh versions):
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
set_repo_var() {
  local name="$1"
  local value="$2"
  gh api -X PATCH "repos/${REPO}/actions/variables/${name}" -f name="${name}" -f value="${value}" >/dev/null 2>&1 || \
    gh api -X POST "repos/${REPO}/actions/variables" -f name="${name}" -f value="${value}" >/dev/null
}

set_repo_var SSH_HOST "v734690.hosted-by-vdsina.com"
set_repo_var SSH_USER "root"
set_repo_var DEPLOY_PATH "/opt/proxy_vpn"
set_repo_var VPN_PANEL_DOMAIN "vpn.example.com"
set_repo_var CADDY_HTTP_PORT "80"
set_repo_var CADDY_HTTPS_PORT "443"
set_repo_var XRAY_PORT "8443"
set_repo_var WG_PORT "51820"
set_repo_var ADMIN_USERNAME "admin"
set_repo_var ADMIN_EMAIL "admin@example.com"
set_repo_var PREFLIGHT_MAX_AGE_MIN "60"

# Secrets:
openssl rand -base64 48 | tr -d '\n' | gh secret set APP_SECRET_KEY
gh secret set ADMIN_PASSWORD --body "CHANGE_ME_STRONG_ADMIN_PASSWORD"
gh secret set DEPLOY_SSH_KEY < ~/.ssh/id_ed25519

12) Trigger CI:
# first run preflight
# then run deploy
# workflows:
# - Preflight Production
# - Deploy Production

EOF
