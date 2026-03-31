#!/usr/bin/env bash
# Capacity baseline/guardrail check for proxy-vpn single-server setup.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

WINDOW_MINUTES="${WINDOW_MINUTES:-60}"
TARGET_ACTIVE_USERS="${TARGET_ACTIVE_USERS:-15}"
CPU_WARN_P95="${CPU_WARN_P95:-70}"
CPU_CRIT_P95="${CPU_CRIT_P95:-80}"
RAM_WARN_P95="${RAM_WARN_P95:-80}"
RAM_CRIT_P95="${RAM_CRIT_P95:-85}"
DISK_WARN_P95="${DISK_WARN_P95:-85}"
DISK_CRIT_P95="${DISK_CRIT_P95:-92}"
OUTPUT_PATH="${OUTPUT_PATH:-logs/capacity-check-latest.txt}"

mkdir -p "$(dirname "${OUTPUT_PATH}")"

if ! docker info >/dev/null 2>&1; then
  die "Docker daemon is not running or not accessible."
fi

if ! docker ps --format '{{.Names}}' | rg '^proxy-vpn-api$' >/dev/null 2>&1; then
  die "Container proxy-vpn-api is not running."
fi

report_json="$(
docker exec proxy-vpn-api python - <<'PY'
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import os

db_path = Path("/data/app.db")
if not db_path.exists():
    print(json.dumps({"status": "error", "reason": f"db not found: {db_path}"}))
    raise SystemExit(0)

window_minutes = int(os.getenv("WINDOW_MINUTES", "60"))
target_active_users = int(os.getenv("TARGET_ACTIVE_USERS", "15"))
cpu_warn = float(os.getenv("CPU_WARN_P95", "70"))
cpu_crit = float(os.getenv("CPU_CRIT_P95", "80"))
ram_warn = float(os.getenv("RAM_WARN_P95", "80"))
ram_crit = float(os.getenv("RAM_CRIT_P95", "85"))
disk_warn = float(os.getenv("DISK_WARN_P95", "85"))
disk_crit = float(os.getenv("DISK_CRIT_P95", "92"))

def pct(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    idx = max(0, min(len(values) - 1, int((len(values) - 1) * p)))
    return float(values[idx])

def classify(value, warn, crit):
    if value >= crit:
        return "critical"
    if value >= warn:
        return "warn"
    return "ok"

con = sqlite3.connect(str(db_path))
con.row_factory = sqlite3.Row
ts_from = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
rows = con.execute(
    """
    SELECT cpu_load_pct, memory_used_pct, disk_used_pct, net_rx_bytes, net_tx_bytes
    FROM metric_samples
    WHERE ts >= ?
    ORDER BY ts ASC
    """,
    (ts_from,),
).fetchall()
last_stats = con.execute(
    """
    SELECT
      COALESCE(COUNT(*), 0) AS active_sessions
    FROM sessions
    WHERE revoked = 0
      AND expires_at > ?
    """,
    (datetime.utcnow().isoformat(),),
).fetchone()
con.close()

if not rows:
    print(json.dumps({"status": "error", "reason": "no metric_samples in selected window"}))
    raise SystemExit(0)

cpu = [float(r["cpu_load_pct"] or 0.0) for r in rows]
mem = [float(r["memory_used_pct"] or 0.0) for r in rows]
disk = [float(r["disk_used_pct"] or 0.0) for r in rows]
rx0 = int(rows[0]["net_rx_bytes"] or 0)
tx0 = int(rows[0]["net_tx_bytes"] or 0)
rx1 = int(rows[-1]["net_rx_bytes"] or 0)
tx1 = int(rows[-1]["net_tx_bytes"] or 0)

cpu_p95 = round(pct(cpu, 0.95), 2)
mem_p95 = round(pct(mem, 0.95), 2)
disk_p95 = round(pct(disk, 0.95), 2)
cpu_avg = round(sum(cpu) / len(cpu), 2)
mem_avg = round(sum(mem) / len(mem), 2)
disk_avg = round(sum(disk) / len(disk), 2)
traffic_rx = max(0, rx1 - rx0)
traffic_tx = max(0, tx1 - tx0)
active_sessions = int(last_stats["active_sessions"] or 0)

signals = {
    "cpu": classify(cpu_p95, cpu_warn, cpu_crit),
    "memory": classify(mem_p95, ram_warn, ram_crit),
    "disk": classify(disk_p95, disk_warn, disk_crit),
    "concurrency": "warn" if active_sessions > target_active_users else "ok",
}
overall = "ok"
if "critical" in signals.values():
    overall = "critical"
elif "warn" in signals.values():
    overall = "warn"

print(
    json.dumps(
        {
            "status": "ok",
            "window_minutes": window_minutes,
            "target_active_users": target_active_users,
            "samples": len(rows),
            "active_sessions": active_sessions,
            "overall": overall,
            "signals": signals,
            "avg": {"cpu_pct": cpu_avg, "mem_pct": mem_avg, "disk_pct": disk_avg},
            "p95": {"cpu_pct": cpu_p95, "mem_pct": mem_p95, "disk_pct": disk_p95},
            "traffic_window_bytes": {"rx": traffic_rx, "tx": traffic_tx},
            "thresholds": {
                "cpu_warn_p95": cpu_warn,
                "cpu_crit_p95": cpu_crit,
                "ram_warn_p95": ram_warn,
                "ram_crit_p95": ram_crit,
                "disk_warn_p95": disk_warn,
                "disk_crit_p95": disk_crit,
            },
        },
        ensure_ascii=True,
    )
)
PY
)"

if [ "$(printf '%s' "${report_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')" != "ok" ]; then
  log "${report_json}" | tee "${OUTPUT_PATH}"
  die "Capacity check failed."
fi

python3 - "${report_json}" "${OUTPUT_PATH}" <<'PY'
import json
import sys
from datetime import datetime, timezone

report = json.loads(sys.argv[1])
out_path = sys.argv[2]

def fmt_bytes(n):
    n = float(n)
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.2f} {units[i]}"

lines = []
lines.append("proxy-vpn capacity check")
lines.append(f"ts_utc={datetime.now(timezone.utc).isoformat()}")
lines.append(f"window_minutes={report['window_minutes']} samples={report['samples']}")
lines.append(f"target_active_users={report['target_active_users']} active_sessions={report['active_sessions']}")
lines.append(f"overall={report['overall']}")
lines.append("")
lines.append(f"cpu_avg={report['avg']['cpu_pct']}% cpu_p95={report['p95']['cpu_pct']}% signal={report['signals']['cpu']}")
lines.append(f"mem_avg={report['avg']['mem_pct']}% mem_p95={report['p95']['mem_pct']}% signal={report['signals']['memory']}")
lines.append(f"disk_avg={report['avg']['disk_pct']}% disk_p95={report['p95']['disk_pct']}% signal={report['signals']['disk']}")
lines.append(
    f"traffic_window=RX {fmt_bytes(report['traffic_window_bytes']['rx'])} / TX {fmt_bytes(report['traffic_window_bytes']['tx'])}"
)
lines.append("")
lines.append(
    "thresholds="
    + ",".join(
        [
            f"cpu_warn_p95:{report['thresholds']['cpu_warn_p95']}",
            f"cpu_crit_p95:{report['thresholds']['cpu_crit_p95']}",
            f"ram_warn_p95:{report['thresholds']['ram_warn_p95']}",
            f"ram_crit_p95:{report['thresholds']['ram_crit_p95']}",
            f"disk_warn_p95:{report['thresholds']['disk_warn_p95']}",
            f"disk_crit_p95:{report['thresholds']['disk_crit_p95']}",
        ]
    )
)

text = "\n".join(lines) + "\n"
print(text, end="")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(text)
PY

log "Saved report: ${OUTPUT_PATH}"
