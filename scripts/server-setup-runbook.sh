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
mkdir -p /opt/proxy_vpn
cd /opt/proxy_vpn
# Clone first (private repo via GitHub deploy key)
test -d .git || git clone git@github.com:SolonnikovDV/proxy_vpn.git .
# Run unified bootstrap; it auto-prompts required values in interactive shell:
sudo bash ./scripts/bootstrap-ubuntu.sh

# Optional non-interactive form:
# TARGET_USER=root DEPLOY_PATH=/opt/proxy_vpn VPN_PANEL_DOMAIN="vpn.example.com" SERVER_PUBLIC_IP="vpn.example.com" \
# ADMIN_USERNAME="admin" ADMIN_EMAIL="admin@example.com" APP_SECRET_KEY_FILE="/etc/proxy-vpn/secrets/app_secret_key" \
# ADMIN_PASSWORD_FILE="/etc/proxy-vpn/secrets/admin_password" BOOTSTRAP_ADMIN_PASSWORD="CHANGE_ME_STRONG_ADMIN_PASSWORD" \
# sudo bash ./scripts/bootstrap-ubuntu.sh

3) Verify generated environment and secret files (run on server):
ls -la /opt/proxy_vpn/.env /etc/proxy-vpn/secrets/app_secret_key /etc/proxy-vpn/secrets/admin_password

4) Preflight (run on server):
bash ./scripts/preflight-prod.sh

5) Start production stack (run on server):
bash ./scripts/run.sh prod up

6) Validate health (run on server):
bash ./scripts/run.sh prod ps
curl -fsS http://127.0.0.1:80/health
MODE=prod HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh

7) Enable scheduled auto-update (run on server):
DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" \
  bash ./scripts/setup-auto-update.sh
systemctl status --no-pager proxy-vpn-auto-update.timer

7.1) Enable scheduled critical backups (run on server):
DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root MODE=prod ON_CALENDAR="daily" RETENTION_COUNT=14 \
  bash ./scripts/setup-backup.sh
systemctl status --no-pager proxy-vpn-backup.timer

7.2) Validate backup integrity gate once (run on server):
INTEGRITY_SCOPE=runtime bash ./scripts/integrity-check.sh

8) Run capacity baseline check (run on server after 1h runtime):
WINDOW_MINUTES=60 TARGET_ACTIVE_USERS=15 bash ./scripts/capacity-check.sh
cat logs/capacity-check-latest.txt

9) Ensure login key is in authorized_keys (run on server):
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# replace placeholder with your real public key:
echo "ssh-ed25519 AAAA...YOUR_PUBLIC_KEY..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
systemctl restart ssh || systemctl restart sshd

10) Configure GitHub Variables/Secrets (from server, interactive inside bootstrap):
# bootstrap step can configure GitHub Actions vars/secrets directly using GitHub token
# if needed, rerun manually on server:
# GITHUB_ACTIONS_REPO="owner/repo" GITHUB_ACTIONS_TOKEN="ghp_xxx" \
#   CONFIGURE_GITHUB_ACTIONS_FROM_SERVER=1 sudo bash ./scripts/bootstrap-ubuntu.sh

11) Operational model:
# - deployment/update is pull-based from server timer (setup-auto-update.sh)
# - critical backups are periodic via setup-backup.sh (db + configs + env + secrets)
# - backup service proceeds only if integrity checks pass (scripts/integrity-check.sh)
# - security-guard container auto-detects brute/ddos/probe and publishes incidents in Admin -> Security
# - SSH keys exist only on server/client, not in GitHub secrets
# - GitHub workflows can run remote deploy/preflight when DEPLOY_SSH_KEY is configured
# - capacity check report should stay "overall=ok" for target active users
# - thresholds: CPU p95 > 80% or RAM p95 > 85% (10-15 min) => upgrade to 2 vCPU / 4 GB
# - if active users trend to 50+, plan split to 2-node topology (panel/api separate from vpn-plane)

EOF
