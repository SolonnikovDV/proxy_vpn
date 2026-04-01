#!/usr/bin/env bash
# Integrity checks for proxy-vpn runtime and CI contract.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

INTEGRITY_SCOPE="${INTEGRITY_SCOPE:-runtime}" # runtime | ci | all

require_file_nonempty() {
  local p="$1"
  [ -f "${p}" ] || die "Missing file: ${p}"
  [ -s "${p}" ] || die "Empty file: ${p}"
}

check_repo_contract() {
  log "[repo] Checking repository integrity contract..."
  require_file_nonempty "compose.yaml"
  require_file_nonempty ".env.local.example"
  require_file_nonempty ".env.production.example"
  require_file_nonempty "api/app/main.py"
  require_file_nonempty "scripts/backup-critical.sh"
  require_file_nonempty "scripts/restore-critical.sh"
  require_file_nonempty "scripts/setup-backup.sh"
  require_file_nonempty "scripts/pull-audit.sh"
  require_file_nonempty "scripts/bootstrap-ubuntu.sh"
  require_file_nonempty "security_guard/app.py"

  grep -Eq "name:[[:space:]]*proxy-vpn" compose.yaml || die "compose.yaml missing project name proxy-vpn"
  grep -Eq "name:[[:space:]]*proxy-vpn_api_data" compose.yaml || die "compose.yaml missing api data volume"
  grep -Eq "security-guard:" compose.yaml || die "compose.yaml missing security-guard service"

  for k in APP_SECRET_KEY_FILE ADMIN_PASSWORD_FILE; do
    grep -Eq "^${k}=" .env.production.example || die ".env.production.example missing ${k}"
  done

  for t in users sessions metric_samples system_config; do
    grep -Eq "CREATE TABLE IF NOT EXISTS ${t}" api/app/main.py || die "main.py missing table ${t}"
  done

  # Ensure backups are guarded by integrity checks before snapshot creation.
  grep -Eq "integrity-check\\.sh" scripts/backup-critical.sh || die "backup-critical.sh is not gated by integrity checks"
  grep -Eq "LOCAL_CHANGES_POLICY=.*stash" scripts/auto-update.sh || die "auto-update.sh missing local change preservation policy"

  # Bootstrap contract: some vars have defaults, some are interactive-required.
  for k in TARGET_USER DEPLOY_PATH CLONE_REPO AUTO_PULL_REPO CONFIGURE_GITHUB_REPO_ACCESS AUTO_GENERATE_VPN_CONFIGS CONFIGURE_GITHUB_ACTIONS_FROM_SERVER APP_SECRET_KEY_FILE ADMIN_PASSWORD_FILE; do
    grep -Eq "^${k}=\\\"\\$\\{${k}:-.*\\}\\\"" scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing default assignment for ${k}"
  done

  # Interactive-required values (no silent defaults in interactive mode).
  grep -Eq 'VPN_PANEL_DOMAIN=""' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh must force manual VPN_PANEL_DOMAIN input in interactive mode"
  grep -Eq 'SERVER_PUBLIC_IP=""' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh must force manual SERVER_PUBLIC_IP input in interactive mode"
  grep -Eq 'prompt_value VPN_PANEL_DOMAIN "Enter public panel domain \(VPN_PANEL_DOMAIN\)" ""' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing VPN_PANEL_DOMAIN prompt"
  grep -Eq 'prompt_value SERVER_PUBLIC_IP "Enter public server host/IP for VPN configs \(SERVER_PUBLIC_IP\)" ""' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing SERVER_PUBLIC_IP prompt"
  grep -Eq 'prompt_value ADMIN_EMAIL "Enter admin email \(ADMIN_EMAIL\)" "admin@\$\{VPN_PANEL_DOMAIN\}"' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing ADMIN_EMAIL prompt"
  grep -Eq 'prompt_value BOOTSTRAP_ADMIN_PASSWORD "Enter admin password \(leave empty to autogenerate\)" "" "1"' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing admin password prompt"
  grep -Eq 'prompt_value GITHUB_ACTIONS_TOKEN "GitHub token with repo/actions permissions" "" "1"' scripts/bootstrap-ubuntu.sh || die "bootstrap-ubuntu.sh missing GitHub token prompt"
}

check_runtime_state() {
  log "[runtime] Checking runtime integrity for backup..."
  require_file_nonempty ".env"
  require_file_nonempty "xray/config.json"
  require_file_nonempty "wireguard/conf/wg0.conf"

  python3 - <<'PY'
import json
from pathlib import Path
json.loads(Path("xray/config.json").read_text(encoding="utf-8"))
PY

  grep -Eq "^\[Interface\]" wireguard/conf/wg0.conf || die "wireguard/conf/wg0.conf invalid: [Interface] not found"

  tmp_db="$(mktemp "/tmp/proxy-vpn-integrity-db.XXXXXX")"
  trap 'rm -f "${tmp_db}" >/dev/null 2>&1 || true' RETURN

  copy_db_from_volume() {
    docker run --rm \
      -v proxy-vpn_api_data:/data \
      -v "$(dirname "${tmp_db}"):/backup" \
      alpine:3.20 sh -lc 'if [ -f /data/app.db ]; then cp -f /data/app.db /backup/$(basename "'"${tmp_db}"'"); fi'
  }

  if docker ps --format '{{.Names}}' | grep -Eq '^proxy-vpn-api$'; then
    log "[runtime] Exporting db snapshot from proxy-vpn-api container..."
    docker exec proxy-vpn-api python - <<'PY'
import sqlite3
src = sqlite3.connect('/data/app.db')
dst = sqlite3.connect('/tmp/app-integrity.db')
src.backup(dst)
dst.close()
src.close()
PY
    if docker cp "proxy-vpn-api:/tmp/app-integrity.db" "${tmp_db}"; then
      docker exec proxy-vpn-api rm -f /tmp/app-integrity.db >/dev/null 2>&1 || true
    else
      log "[runtime] Container snapshot unavailable, fallback to volume db path..."
      copy_db_from_volume
    fi
  else
    log "[runtime] Api container is down, reading db from docker volume..."
    copy_db_from_volume
  fi

  [ -f "${tmp_db}" ] && [ -s "${tmp_db}" ] || die "Unable to read app.db from runtime sources"

  python3 - "${tmp_db}" <<'PY'
import sqlite3
import sys
path = sys.argv[1]
conn = sqlite3.connect(path)
cur = conn.cursor()
qc = cur.execute("PRAGMA quick_check;").fetchall()
if not qc or qc[0][0].lower() != "ok":
    raise SystemExit(f"PRAGMA quick_check failed: {qc}")
fk = cur.execute("PRAGMA foreign_key_check;").fetchall()
if fk:
    raise SystemExit(f"PRAGMA foreign_key_check failed: {fk[:5]}")
required = {
    "users",
    "sessions",
    "login_attempts",
    "metric_samples",
    "user_traffic_samples",
    "wg_peer_bindings",
    "wg_peer_counters",
    "user_wireguard_traffic_samples",
    "xray_client_bindings",
    "xray_client_counters",
    "user_xray_traffic_samples",
    "user_access_profiles",
    "registration_requests",
    "system_config",
}
rows = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
present = {r[0] for r in rows}
missing = sorted(required - present)
if missing:
    raise SystemExit(f"Missing required tables: {missing}")
cur.execute("SELECT COUNT(*) FROM users").fetchone()
cur.execute("SELECT COUNT(*) FROM metric_samples").fetchone()
conn.close()
PY

  tmp_sec_db="$(mktemp "/tmp/proxy-vpn-security-db.XXXXXX")"
  trap 'rm -f "${tmp_sec_db}" >/dev/null 2>&1 || true' RETURN
  docker run --rm \
    -v proxy-vpn_security_data:/data \
    -v "$(dirname "${tmp_sec_db}"):/backup" \
    alpine:3.20 sh -lc 'if [ -f /data/security.db ]; then cp -f /data/security.db /backup/$(basename "'"${tmp_sec_db}"'"); fi'
  if [ -s "${tmp_sec_db}" ]; then
    python3 - "${tmp_sec_db}" <<'PY'
import sqlite3
import sys
conn = sqlite3.connect(sys.argv[1])
qc = conn.execute("PRAGMA quick_check;").fetchall()
if not qc or qc[0][0].lower() != "ok":
    raise SystemExit(f"security.db quick_check failed: {qc}")
tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
for name in ("security_events", "blocked_ips"):
    if name not in tables:
        raise SystemExit(f"security.db missing table: {name}")
conn.close()
PY
  fi

  python3 - <<'PY'
from pathlib import Path
required = ("APP_SECRET_KEY_FILE", "ADMIN_PASSWORD_FILE")
pairs = {}
for line in Path(".env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    pairs[k.strip()] = v.strip().strip('"').strip("'")
for key in required:
    path = pairs.get(key)
    if path:
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            raise SystemExit(f"Secret file is missing or empty: {key}={path}")
PY
}

case "${INTEGRITY_SCOPE}" in
  ci)
    check_repo_contract
    ;;
  runtime)
    check_repo_contract
    check_runtime_state
    ;;
  all)
    check_repo_contract
    check_runtime_state
    ;;
  *)
    die "Unknown INTEGRITY_SCOPE=${INTEGRITY_SCOPE}. Use ci|runtime|all."
    ;;
esac

log "Integrity checks passed (scope=${INTEGRITY_SCOPE})."
