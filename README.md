# proxy-vpn

Docker-based stack: WireGuard + Xray + FastAPI + Caddy.

## Quick Start (server-only)

Minimal path when you start from a clean Ubuntu server and want to configure everything from server console:

```bash
# 1) Connect to server and install base packages
apt-get update -y && apt-get install -y git curl

# 2) Clone private repository (ensure deploy key is available)
mkdir -p /opt/proxy_vpn
cd /opt/proxy_vpn
test -d .git || git clone git@github.com:SolonnikovDV/proxy_vpn.git .

# 3) Run interactive bootstrap (asks required values, configures repo/keys/vpn/env)
sudo bash ./scripts/bootstrap-ubuntu.sh

# 4) Start production stack
bash ./scripts/run.sh prod up

# 5) Validate health
MODE=prod HEALTH_TIMEOUT=120 bash ./scripts/healthcheck-stack.sh

# 6) Enable scheduled auto-update and backups
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" UPDATE_APPROVAL_REQUIRED=0 \
  bash ./scripts/setup-auto-update.sh
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root MODE=prod ON_CALENDAR="daily" RETENTION_COUNT=14 \
  bash ./scripts/setup-backup.sh
```

## Local dev

```bash
bash ./scripts/run.sh local up
```

`test-local.sh` uses `Caddyfile.dev` and picks free host ports when needed.

Local UI URLs after startup:
- `/` - landing page
- `/login` - login/register
- `/cabinet` - user page (requires auth)
- `/admin` - admin page (requires admin role)

Default local admin credentials:
- username: `admin`
- password: `admin123!`

Security behavior in this build:
- CSRF token required for auth POST endpoints (`register`, `login`, `logout`, `logout-all`)
- signed session cookie + server-side session table (supports session revocation)
- login brute-force protection (lock per username+IP after repeated failures)
- dedicated `security-guard` container tracks attack telemetry (DDoS/brute/probe), auto-blocks abusive IPs, and provides geo-localized incidents for Admin -> Security
- registration requires admin approval (pending requests workflow)
- admin can approve/reject requests and create user/admin accounts
- Exact per-user traffic mode: bind WireGuard peer public keys and Xray client emails to users in Admin -> Traffic
- Human-readable service dashboard in Admin -> Overview with container states and log modal for pending/error
- In-app release banner + About page with version and update controls

Rate-limit knobs for auth endpoints:
- `LOGIN_MAX_ATTEMPTS` (default `5`)
- `LOGIN_WINDOW_MINUTES` (default `10`)
- `LOGIN_LOCK_MINUTES` (default `15`)
- `DASHBOARD_REFRESH_SECONDS` (default `30`, configurable in Admin -> Configurator)
- `SECURITY_DEFAULT_BLOCK_SECONDS` (default `900`, block duration for detected attacks)
- `SECURITY_GEOIP_ENABLED` (default `1`, resolve country/city/asn in security events)
- `SECURITY_HTTP_WINDOW_SECONDS` + `SECURITY_HTTP_MAX_REQUESTS` (HTTP flood detection window/rate)
- `SECURITY_SERVER_CHECK_INTERVAL_SECONDS` + `SECURITY_SERVER_EVENT_COOLDOWN_SECONDS` (server-state security checks and alert cooldown)

Proxy bypass whitelist (traffic saving):
- purpose: do not route selected resources through VPN when they are not blocked/slowed in Russia
- storage: `config/proxy-bypass-rules.txt` (editable plain text file)
- format per line: `resource,true|false`
  - `false` = Direct/Bypass (VPN disabled for this resource)
  - `true` = keep VPN route
- examples: `yandex.ru,false`, `vk.com,false`, `gosuslugi.ru,false`
- admin UI editing: `Admin -> Configurator -> Proxy bypass resources (Direct/Bypass)` (writes back to the same file)

Unified launcher commands:
- `bash ./scripts/run.sh local up`
- `bash ./scripts/run.sh local down`
- `bash ./scripts/run.sh local logs`
- `bash ./scripts/run.sh local ps`
- `bash ./scripts/test-smoke.sh` (creates/uses `.venv`, installs dev deps, runs `pytest -q tests/test_smoke.py`)
- `WINDOW_MINUTES=60 TARGET_ACTIVE_USERS=15 bash ./scripts/capacity-check.sh` (capacity baseline report)

Recommended clients by platform (approved baseline):
- iOS: `Karing`
- Android: `v2rayNG`
- Windows: `v2rayN`
- macOS: `V2rayU`
- Linux: `Karing`

WireGuard client compatibility note (paired mode):
- paired mode tracks WireGuard and Xray independently per user and can recommend manual primary/fallback switch
- if WG diagnostics show `data_path_not_confirmed` / `client_attempt_seen=false`, server path is usually healthy but device routing is not applied
- on iOS, check tunnel is active for the exact profile, disable iCloud Private Relay / "Limit IP Address Tracking" for current network, then retry
- Admin WG validator is the source of truth for this case: `/admin` -> `Traffic` -> `WG bindings` -> `Diagnostics`

## Production

1. Prepare environment:
- `.env` is auto-synced from `.env.production.example` by `scripts/run.sh` and `scripts/auto-update.sh`
- existing values in `.env` are preserved and missing keys are filled from the template

Why `.env` exists:
- `.env.local.example` and `.env.production.example` are templates
- `.env` is auto-generated/synced runtime config consumed by Docker Compose and app services
- sync script keeps your current `.env` values and adds missing keys from template

2. Edit `.env`:
- `VPN_PANEL_DOMAIN` -> your real domain (DNS A record to server IP)
- `WG_PORT`, `XRAY_PORT` as needed
- keep `CADDYFILE_PATH=Caddyfile.prod`
- recommended: set `APP_SECRET_KEY_FILE` and `ADMIN_PASSWORD_FILE` to root-only files outside repository

Current external exposure model (single server):
- `443/tcp` -> Caddy (panel/API, TLS)
- `8443/tcp` -> Xray (VLESS+REALITY)
- `51820/udp` -> WireGuard

For target scale up to `~15 active users`, keep single-node topology and avoid external L4/L7 load balancer.

Recommended secrets setup on server:

```bash
sudo install -d -m 700 /etc/proxy-vpn/secrets
sudo sh -c "openssl rand -base64 48 | tr -d '\n' > /etc/proxy-vpn/secrets/app_secret_key"
sudo sh -c "printf '%s' 'CHANGE_ME_STRONG_ADMIN_PASSWORD' > /etc/proxy-vpn/secrets/admin_password"
sudo chmod 600 /etc/proxy-vpn/secrets/app_secret_key /etc/proxy-vpn/secrets/admin_password
```

3. (Optional manual mode) Generate WireGuard server+client config:

```bash
SERVER_PUBLIC_IP=YOUR_SERVER_IP_OR_DOMAIN bash ./scripts/setup-wireguard.sh
```

4. (Optional manual mode) Generate Xray VLESS+REALITY config:

```bash
SERVER_PUBLIC_IP=YOUR_SERVER_IP_OR_DOMAIN XRAY_PORT=8443 bash ./scripts/setup-xray-reality.sh
```

Important for seamless client updates:
- `setup-xray-reality.sh` reuses existing REALITY keypair, Short ID and primary client UUID by default (no client-side config rotation on rebuild)
- force rotation only when explicitly needed: `FORCE_REGENERATE_XRAY_KEYS=1 bash ./scripts/setup-xray-reality.sh`

This config includes Xray `StatsService` and is compatible with exact per-user traffic collection in admin UI.

Generated files:
- `wireguard/conf/wg0.conf` and `wireguard/conf/client1.conf`
- `xray/config.json` and `xray/client-connection.txt`

5. (Optional) Batch-generate multiple clients for WG + Xray:

```bash
CLIENT_NAMES=alice,bob,charlie SERVER_PUBLIC_IP=YOUR_SERVER_IP_OR_DOMAIN XRAY_PORT=8443 bash ./scripts/setup-batch-clients.sh
```

Generated per-client files:
- `wireguard/conf/<name>.conf`
- `xray/clients/<name>.txt`

6. (Optional) Export all clients to one CSV (for panel/billing import):

```bash
bash ./scripts/export-clients-csv.sh
```

Custom output path:

```bash
OUTPUT_PATH=exports/my-clients.csv bash ./scripts/export-clients-csv.sh
```

JSON export (for direct backend import):

```bash
bash ./scripts/export-clients-json.sh
```

Custom JSON output path:

```bash
OUTPUT_PATH=exports/my-clients.json bash ./scripts/export-clients-json.sh
```

7. Preflight (no deploy, validation only):

```bash
bash ./scripts/preflight-prod.sh
```

By default, preflight does **not** auto-regenerate invalid Xray REALITY config to avoid breaking existing clients.
- explicit opt-in (maintenance window only): `ALLOW_XRAY_REGENERATE_ON_INVALID=1 bash ./scripts/preflight-prod.sh`

8. Deploy (recommended):

```bash
bash ./scripts/deploy-prod.sh
```

`deploy-prod.sh` includes post-deploy health check and safe rollback:
- checks `http://127.0.0.1:${CADDY_HTTP_PORT}/health`
- if check fails, automatically redeploys previous git revision and re-checks health

Or via unified launcher:

```bash
bash ./scripts/run.sh prod up
```

## GitHub Secrets/Variables deploy

Default recommended mode keeps app secrets on server in root-only files (not in repository).
For GitHub remote workflows (`Preflight Production`, `Deploy Production`), `DEPLOY_SSH_KEY` is required.

Workflow:
- `.github/workflows/ci-checks.yml`
- `.github/workflows/deploy-prod.yml`
- `.github/workflows/preflight-prod.yml`
- `.github/workflows/nightly-self-check.yml`
- runs preflight-only or preflight+deploy on the target host over SSH

CI/CD integrity contract:
- `ci-checks`, `deploy-prod`, `preflight-prod`, `nightly-self-check` run `INTEGRITY_SCOPE=ci bash ./scripts/integrity-check.sh`
- this contract validates bootstrap/env setup rules in `scripts/bootstrap-ubuntu.sh`:
  - part of variables must keep default values in script (non-interactive safe reruns)
  - critical values must be requested interactively (for example `VPN_PANEL_DOMAIN`, `SERVER_PUBLIC_IP`, admin credentials/token prompts)
- if this contract is broken, workflow fails as repository/config regression
- missing deploy-access inputs (`DEPLOY_SSH_KEY`, `SSH_HOST`, `SSH_USER`, `DEPLOY_PATH`) do **not** fail stability checks; remote SSH steps are logged and skipped as non-blocking

Fail vs Non-blocking matrix:

| Condition | CI result | Behavior |
|---|---|---|
| `INTEGRITY_SCOPE=ci` contract broken (repo/bootstrap regression) | **FAIL** | Workflow stops, regression must be fixed in repository/scripts |
| Runtime integrity broken in backup (`INTEGRITY_SCOPE=runtime`) | **FAIL** | Backup is not created, integrity reason is written to backup status |
| Missing deploy remote inputs (`DEPLOY_SSH_KEY`, `SSH_HOST`, `SSH_USER`, `DEPLOY_PATH`) | **NON-BLOCKING** | CI stability checks remain valid; remote SSH steps are skipped with explicit logs |
| Missing optional render inputs when `RENDER_ENV_FROM_CI=1` | **NON-BLOCKING** | Remote preflight/deploy is skipped; workflows report which env inputs are missing |

Create GitHub **Secrets**:
- required for GitHub-initiated remote deploy/preflight over SSH: `DEPLOY_SSH_KEY`
- bootstrap can configure this from server interactively (`CONFIGURE_GITHUB_ACTIONS_FROM_SERVER=1`)

Create GitHub **Variables**:
- Minimal: `SSH_HOST`, `SSH_USER`, `DEPLOY_PATH`, `VPN_PANEL_DOMAIN` (or `SSH_HOST`/`SSH_USER` via secrets)
- Application identity/path variables: `ADMIN_USERNAME`, `ADMIN_EMAIL`, `APP_SECRET_KEY_FILE`, `ADMIN_PASSWORD_FILE`
- Optional: `PREFLIGHT_MAX_AGE_MIN` (default `60`)
- Optional mode flag: `RENDER_ENV_FROM_CI` (`0` by default)
- Optional (only when `RENDER_ENV_FROM_CI=1`): port variables and inline secret values

Configure these in one command block with:

```bash
bash ./scripts/setup-github-config.sh
```

Single-script examples:

```bash
# Recommended (RENDER_ENV_FROM_CI=0, secrets stay on server files)
SSH_HOST="v734690.hosted-by-vdsina.com" \
SSH_USER="root" \
DEPLOY_PATH="/opt/proxy_vpn" \
VPN_PANEL_DOMAIN="v734690.hosted-by-vdsina.com" \
ADMIN_USERNAME="admin" \
ADMIN_EMAIL="admin@example.com" \
APP_SECRET_KEY_FILE="/etc/proxy-vpn/secrets/app_secret_key" \
ADMIN_PASSWORD_FILE="/etc/proxy-vpn/secrets/admin_password" \
RENDER_ENV_FROM_CI="0" \
bash ./scripts/setup-github-config.sh

# Optional: inline app secrets for RENDER_ENV_FROM_CI=1
SSH_HOST="v734690.hosted-by-vdsina.com" \
SSH_USER="root" \
DEPLOY_PATH="/opt/proxy_vpn" \
VPN_PANEL_DOMAIN="v734690.hosted-by-vdsina.com" \
RENDER_ENV_FROM_CI="1" \
APP_SECRET_KEY="REPLACE_WITH_STRONG_RANDOM_VALUE" \
ADMIN_PASSWORD="REPLACE_WITH_STRONG_ADMIN_PASSWORD" \
bash ./scripts/setup-github-config.sh
```

Then trigger workflow **Deploy Production** (`workflow_dispatch`) from GitHub Actions.

Default recommended mode:
- keep production `.env` on server
- set `RENDER_ENV_FROM_CI=0`
- use server-side timer (`setup-auto-update.sh`) for pull-based deploy
- do not store SSH keys in GitHub

Recommended protection:
- create GitHub Environment `production`
- enable **required reviewers** for this environment
- both workflows use `environment: production`, so deployment requires manual approval
- run **Preflight Production** first, then **Deploy Production**

Manual alternative:

```bash
docker compose -f compose.yaml -f compose.prod.yaml up -d --build
```

Pre-check before deploy:
- ensure `CADDY_HTTPS_PORT` and `XRAY_PORT` are different on one host
- ensure `VPN_PANEL_DOMAIN` points to server IP

## Caddy configs

- `caddy/Caddyfile.dev` - localhost + `tls internal`, for local checks.
- `caddy/Caddyfile.prod` - real domain + automatic HTTPS (Let's Encrypt).

Compose mounts selected file via:

```env
CADDYFILE_PATH=Caddyfile.dev
```

For production set:

```env
CADDYFILE_PATH=Caddyfile.prod
```

## Bare Ubuntu bootstrap

Run from the cloned repository on server:

```bash
cd /opt/proxy_vpn
sudo bash ./scripts/bootstrap-ubuntu.sh
```

In interactive mode, bootstrap asks required values in console (including `VPN_PANEL_DOMAIN`, `SERVER_PUBLIC_IP`, `ADMIN_EMAIL`, admin password) and can also configure GitHub Actions vars/secrets directly from server (with GitHub token). For `VPN_PANEL_DOMAIN` and `SERVER_PUBLIC_IP`, no defaults are used; values must be entered explicitly.
For non-interactive runs, pass env vars explicitly.

What it does:
- installs Docker Engine + Docker Compose plugin
- installs Git + OpenSSH client/server
- installs and configures UFW (SSH + panel/API + Xray + WireGuard ports)
- installs and enables fail2ban for SSH protection
- installs and enables unattended-upgrades
- enables Docker service
- enables SSH service (`ssh`/`sshd`)
- configures GitHub repository SSH access (generates deploy key, validates access, supports pre-seeded key)
- clones repository by SSH URL into deploy path (and auto-pulls latest commit on rerun)
- auto-generates WireGuard and Xray REALITY configs for production
- creates secret files (`APP_SECRET_KEY_FILE`, `ADMIN_PASSWORD_FILE`) if missing
- renders `${DEPLOY_PATH}/.env` with app/runtime variables and secret file paths
- can configure GitHub Actions vars/secrets from server side (no local setup required)

Optional bootstrap flags:
- `FORCE_ROTATE_SECRETS=1` - rotate secret files even if they already exist
- `PRINT_GENERATED_ADMIN_PASSWORD=1` - when admin password is auto-generated, save it to a root-only report file
- `GENERATED_ADMIN_PASSWORD_REPORT_PATH=/root/proxy-vpn-bootstrap-admin-password.txt` - custom report file path
- `ENABLE_UFW=0` - skip firewall setup (not recommended)
- `ENABLE_FAIL2BAN=0` - skip fail2ban setup (not recommended)
- `ENABLE_UNATTENDED_UPGRADES=0` - skip security auto-updates
- `SSH_PORT=22` - custom SSH port for UFW/fail2ban profile
- `AUTO_PULL_REPO=0` - skip auto `git pull --ff-only` on existing clone
- `AUTO_PULL_LOCAL_CHANGES_POLICY=stash|commit|fail` - behavior when existing clone has local changes before bootstrap auto-pull (default `stash`)
- `AUTO_PULL_LOCAL_CHANGES_COMMIT_MESSAGE="..."` - commit message used when `AUTO_PULL_LOCAL_CHANGES_POLICY=commit`
- `AUTO_GENERATE_VPN_CONFIGS=0` - skip automatic WireGuard/Xray config generation
- `FORCE_REGENERATE_VPN_CONFIGS=1` - force regeneration of WireGuard/Xray configs
- `CONFIGURE_GITHUB_REPO_ACCESS=0` - skip GitHub SSH key management and validation
- `GITHUB_DEPLOY_KEY_B64=<base64-private-key>` - pre-seed deploy key for non-interactive bootstrap
- `CONFIGURE_GITHUB_ACTIONS_FROM_SERVER=0` - skip server-side GitHub Actions vars/secrets setup
- `GITHUB_ACTIONS_REPO=owner/repo` - explicit repository for server-side GitHub Actions config
- `GITHUB_ACTIONS_TOKEN=<token>` - token for server-side GitHub Actions config
- `GITHUB_ACTIONS_INCLUDE_SSH_PASSWORD=1` - additionally store `SSH_PASSWORD` secret from interactive prompt

If you want to prepare server environment first and clone later:

```bash
sudo TARGET_USER=root DEPLOY_PATH=/opt/proxy_vpn CLONE_REPO=0 bash ./scripts/bootstrap-ubuntu.sh
```

Prerequisite:
- server must have SSH key configured to access the private GitHub repository.

## GitHub Actions config paths

Two supported ways:
- server-side (recommended for bare machine): bootstrap interactive flow with `CONFIGURE_GITHUB_ACTIONS_FROM_SERVER=1`
- manual script mode: `bash ./scripts/setup-github-config.sh`

Manual script example:

```bash
SSH_HOST="v734690.hosted-by-vdsina.com" \
SSH_USER="root" \
DEPLOY_PATH="/opt/proxy_vpn" \
VPN_PANEL_DOMAIN="v734690.hosted-by-vdsina.com" \
DEPLOY_SSH_KEY_PATH="$HOME/.ssh/id_ed25519" \
bash ./scripts/setup-github-config.sh
```

Local login helper (reads `SSH_HOST`, `SSH_USER`, `SSH_PASSWORD` from env):

```bash
brew install hudochenkov/sshpass/sshpass
SSH_HOST="v734690.hosted-by-vdsina.com" SSH_USER="root" SSH_PASSWORD="CHANGE_ME_SERVER_PASSWORD" \
  bash ./scripts/login-server.sh
```

Run a single remote command:

```bash
SSH_HOST="v734690.hosted-by-vdsina.com" SSH_USER="root" SSH_PASSWORD="CHANGE_ME_SERVER_PASSWORD" \
  bash ./scripts/login-server.sh "echo ok"
```

## Scheduled auto-update (CD stage)

Install systemd timer to periodically sync latest `main` and rebuild stack when changed:

```bash
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" \
  REPO_SYNC_STRATEGY=mirror LOCAL_CHANGES_POLICY=stash REQUIRE_GREEN_CI=1 \
  GITHUB_REPO="owner/repo" GITHUB_API_TOKEN="<token>" \
  bash ./scripts/setup-auto-update.sh
```

Default production policy is fully automatic (`UPDATE_APPROVAL_REQUIRED=0`, `REPO_SYNC_STRATEGY=mirror`):
- timer checks remote updates and waits for green CI (`REQUIRE_GREEN_CI=1`)
- when green, server clone is force-synced to `origin/main` (`git reset --hard` + `git clean -fd`)
- production stack is rebuilt and health-checked automatically
- resulting runtime matches repository state 1:1 (same as local code for that commit)

To keep old approval-based behavior:

```bash
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" \
  UPDATE_APPROVAL_REQUIRED=1 REPO_SYNC_STRATEGY=pull bash ./scripts/setup-auto-update.sh
```

Auto-update also includes safe rollback:
- after update, runs health check through Caddy and verifies `proxy-vpn-security-guard` container is running
- if health check fails, restores previous commit and redeploys automatically
- writes deployment and rollback history to `logs/deploy-history.log`
- in `REPO_SYNC_STRATEGY=mirror` mode, local changes are stashed (for audit/recovery) and then clone is synced 1:1 with `origin/<branch>`
- in `REPO_SYNC_STRATEGY=pull` mode, `LOCAL_CHANGES_POLICY=stash|commit|fail` controls behavior before pull (`commit` mode uses `git pull --rebase`)
- writes incremental structured update audit to `logs/update-audit.jsonl` (commit titles, changed files, from/to SHA, local-changes handling)
- applies updates only when CI is green if `REQUIRE_GREEN_CI=1` (default)

Manual trigger:

```bash
sudo systemctl start proxy-vpn-auto-update.service
```

View logs:

```bash
journalctl -u proxy-vpn-auto-update.service -n 100 --no-pager
```

Standalone health check:

```bash
MODE=prod HEALTH_TIMEOUT=90 bash ./scripts/healthcheck-stack.sh
```

Deployment history log:

```bash
tail -n 50 logs/deploy-history.log
```

Admin panel (`/admin` -> `Overview`) also shows latest deploy events from this log.

Pull audit helper (manual, with auto stash/commit before pull when needed):

```bash
bash ./scripts/pull-audit.sh
```

Options:
- `APPLY_PULL=0` -> audit only (default, no pull)
- `LOCAL_CHANGES_POLICY=stash|commit|fail` (default `stash`)
- `BRANCH=main` (default `main`)

Example:

```bash
BRANCH=main LOCAL_CHANGES_POLICY=stash bash ./scripts/pull-audit.sh
```

Release metadata and update requests files:
- `logs/app-release-state.json`
- `logs/update-check-request.json`
- `logs/update-apply-request.json`
- `logs/update-audit.jsonl`

Release notes source used by update UI:
- `RELEASE_NOTES.md` (latest section is shown as update notes)

Admin update audit table:
- `/admin` -> `Overview` -> `Updates audit`
- shows incremental update records with date, status, branch, from/to SHA, first commit title, changed files preview, message
- supports filters: status, branch, file text, commit text, date from/to
- API endpoint: `/api/v1/admin/update-audit`

Green CI gate:
- auto-update checks GitHub commit status API (`/repos/<repo>/commits/<sha>/status`)
- for private repositories set `GITHUB_API_TOKEN` in auto-update service environment
- if status is not `success` (or API check fails), update is skipped and recorded in update audit/deploy history

## Backup and restore (critical data)

Create backup snapshot (DB + configs + env + secret files pointed by `.env`):

```bash
bash ./scripts/backup-critical.sh
```

Result:
- archive in `backups/proxy-vpn-backup-<timestamp>.tar.gz`
- symlink `backups/latest-backup.tar.gz`
- retention by count (`RETENTION_COUNT`, default `14`)
- backup is created only after integrity gate passes (`scripts/integrity-check.sh`, scope `runtime`)
- runtime gate includes repository/bootstrap contract checks + runtime checks (db/config/secrets)
- includes Caddy runtime volumes (`caddy-data`, `caddy-config`) in addition to app/security DB and repository runtime files

Restore from snapshot:

```bash
bash ./scripts/restore-critical.sh backups/latest-backup.tar.gz
```

Restore behavior:
- stops stack
- restores `app.db`, `security.db`, Caddy runtime volumes (`caddy-data`, `caddy-config`), `xray/`, `wireguard/conf/`, `.env`, state logs
- restores external secret files (`APP_SECRET_KEY_FILE`, `ADMIN_PASSWORD_FILE`) when present in backup
- starts stack back (can disable: `START_AFTER_RESTORE=0`)

Install scheduled backup timer (recommended):

```bash
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root ON_CALENDAR="daily" RETENTION_COUNT=14 MODE=prod \
  bash ./scripts/setup-backup.sh
```

Integrity checks:

```bash
# Runtime checks used by backup gate (db/config/secrets)
INTEGRITY_SCOPE=runtime bash ./scripts/integrity-check.sh

# CI-compatible contract checks (without runtime docker dependency)
INTEGRITY_SCOPE=ci bash ./scripts/integrity-check.sh
```

CI also runs the same integrity script (`INTEGRITY_SCOPE=ci`) in `.github/workflows/ci-checks.yml`.

Admin panel (`/admin` -> `Overview`) includes **Backup integrity status** card from:
- `logs/backup-status.json`
- API: `/api/v1/admin/backup-status`

Security telemetry API (served by `security-guard` and proxied by API):
- `/api/v1/admin/security/events`
- `/api/v1/admin/security/blocked`
- `/api/v1/admin/security/block` (manual block from admin UI)
- `/api/v1/admin/security/unblock` (manual unblock from admin UI)

Server-state coverage in security layer:
- host resource exhaustion (CPU/RAM/Disk critical)
- service disruption (container stopped/error)
- observability degradation (Docker runtime access issues)

Manual run and logs:

```bash
sudo systemctl start proxy-vpn-backup.service
journalctl -u proxy-vpn-backup.service -n 100 --no-pager
```

## Capacity limits and scaling triggers

Recommended guardrails for `1 vCPU / 2 GB RAM`:
- `CPU p95 > 80%` for 10-15 minutes -> critical (upgrade required)
- `RAM p95 > 85%` sustained -> critical
- `Disk p95 > 92%` -> critical
- active sessions above target (`CAPACITY_TARGET_ACTIVE_USERS`, default `15`) -> warning

Check current state:

```bash
WINDOW_MINUTES=60 TARGET_ACTIVE_USERS=15 bash ./scripts/capacity-check.sh
cat logs/capacity-check-latest.txt
```

Admin panel (`/admin` -> `Overview`) includes live **Capacity guardrails** card based on the same thresholds.

Upgrade path:
1. Keep single-server while overall capacity status is `ok/warn` and warnings are short-lived.
2. Upgrade host to `2 vCPU / 4 GB` when critical thresholds appear or warnings persist.
3. Move to 2-node topology (separate panel/API and VPN plane) only after sustained growth toward `50+ active users`.

## Repository sensitive-data audit

Run local scan before publishing changes:

```bash
bash ./scripts/audit-sensitive.sh
```

CI fail-fast:
- workflow `CI Checks` now starts with dedicated job `sensitive_audit`
- other CI checks run only after this audit passes

## Nightly self-check

GitHub Actions workflow `Nightly Self Check` runs every night (`02:17 UTC`) and can also be started manually.

What it verifies:
- remote host stack health via `scripts/healthcheck-stack.sh`
- remote `docker compose ps` status
- external `https://<VPN_PANEL_DOMAIN>/health` reachability
