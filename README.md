# proxy-vpn

Docker-based stack: WireGuard + Xray + FastAPI + Caddy.

## Local dev

```bash
cp .env.example .env
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
- registration requires admin approval (pending requests workflow)
- admin can approve/reject requests and create user/admin accounts
- Exact per-user traffic mode: bind WireGuard peer public keys and Xray client emails to users in Admin -> Traffic
- Human-readable service dashboard in Admin -> Overview with container states and log modal for pending/error

Unified launcher commands:
- `bash ./scripts/run.sh local up`
- `bash ./scripts/run.sh local down`
- `bash ./scripts/run.sh local logs`
- `bash ./scripts/run.sh local ps`
- `bash ./scripts/test-smoke.sh` (creates/uses `.venv`, installs dev deps, runs `pytest -q tests/test_smoke.py`)

Recommended clients by platform (approved baseline):
- iOS: `Karing`
- Android: `v2rayNG`
- Windows: `v2rayN`
- macOS: `V2rayU`
- Linux: `Karing`

## Production

1. Prepare environment:

```bash
cp .env.prod.example .env
```

2. Edit `.env`:
- `VPN_PANEL_DOMAIN` -> your real domain (DNS A record to server IP)
- `WG_PORT`, `XRAY_PORT` as needed
- keep `CADDYFILE_PATH=Caddyfile.prod`
- set strong values for `APP_SECRET_KEY` and `ADMIN_PASSWORD`

3. Generate WireGuard server+client config:

```bash
SERVER_PUBLIC_IP=YOUR_SERVER_IP_OR_DOMAIN bash ./scripts/setup-wireguard.sh
```

4. Generate Xray VLESS+REALITY config:

```bash
SERVER_PUBLIC_IP=YOUR_SERVER_IP_OR_DOMAIN XRAY_PORT=8443 bash ./scripts/setup-xray-reality.sh
```

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

Production secrets can be stored in GitHub, not in repository files.

Workflow:
- `.github/workflows/deploy-prod.yml`
- `.github/workflows/preflight-prod.yml`
- `.github/workflows/nightly-self-check.yml`
- renders server `.env` from runtime env vars via `scripts/render-prod-env.sh`
- runs preflight-only or preflight+deploy on the target host over SSH

Create GitHub **Secrets**:
- `DEPLOY_SSH_KEY`
- `APP_SECRET_KEY`
- `ADMIN_PASSWORD`

Create GitHub **Variables**:
- `SSH_HOST`
- `SSH_USER`
- `DEPLOY_PATH` (example: `/opt/proxy_vpn`)
- `VPN_PANEL_DOMAIN`
- `CADDY_HTTP_PORT` (usually `80`)
- `CADDY_HTTPS_PORT` (usually `443`)
- `XRAY_PORT` (example: `8443`)
- `WG_PORT` (example: `51820`)
- `ADMIN_USERNAME`
- `ADMIN_EMAIL`
- `PREFLIGHT_MAX_AGE_MIN` (optional, default `60`)

Then trigger workflow **Deploy Production** (`workflow_dispatch`) from GitHub Actions.

Recommended protection:
- create GitHub Environment `production`
- enable **required reviewers** for this environment
- both workflows use `environment: production`, so deployment requires manual approval
- run **Preflight Production** first, then **Deploy Production**
- `Deploy Production` has a preflight gate: it fails if there is no successful recent preflight on the same branch

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

For a fresh Ubuntu 24.04 server, use:

```bash
sudo TARGET_USER=root \
  REPO_SSH_URL=git@github.com:SolonnikovDV/proxy_vpn.git \
  DEPLOY_PATH=/opt/proxy_vpn \
  bash ./scripts/bootstrap-ubuntu.sh
```

What it does:
- installs Docker Engine + Docker Compose plugin
- installs Git + OpenSSH client
- enables Docker service
- clones repository by SSH URL into deploy path

Prerequisite:
- server must have SSH key configured to access the private GitHub repository.

## GitHub SSH on server

Configure deploy SSH key for repository access:

```bash
bash ./scripts/setup-github-ssh.sh
```

Then add printed public key as Deploy Key in GitHub repository (read-only is enough for pull).

## Scheduled auto-update (CD stage)

Install systemd timer to periodically pull latest `main` and rebuild stack when changed:

```bash
sudo DEPLOY_PATH=/opt/proxy_vpn RUN_USER=root BRANCH=main MODE=prod ON_CALENDAR="*:0/15" \
  bash ./scripts/setup-auto-update.sh
```

Auto-update also includes safe rollback:
- after update, runs health check through Caddy
- if health check fails, restores previous commit and redeploys automatically
- writes deployment and rollback history to `logs/deploy-history.log`

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

## Nightly self-check

GitHub Actions workflow `Nightly Self Check` runs every night (`02:17 UTC`) and can also be started manually.

What it verifies:
- remote host stack health via `scripts/healthcheck-stack.sh`
- remote `docker compose ps` status
- external `https://<VPN_PANEL_DOMAIN>/health` reachability
