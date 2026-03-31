#!/usr/bin/env bash
# Synchronize runtime .env from mode template while preserving existing overrides.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

MODE="${1:-}"
[ -n "${MODE}" ] || die "Usage: bash ./scripts/sync-env.sh <local|prod>"

case "${MODE}" in
  local) TEMPLATE=".env.local.example" ;;
  prod) TEMPLATE=".env.production.example" ;;
  *) die "Unknown mode '${MODE}'. Use local|prod." ;;
esac

[ -f "${TEMPLATE}" ] || die "Template not found: ${TEMPLATE}"

python3 - "${TEMPLATE}" ".env" "${MODE}" <<'PY'
import re
import sys
from pathlib import Path

template_path = Path(sys.argv[1])
env_path = Path(sys.argv[2])
mode = sys.argv[3]

line_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

def parse_env(path: Path):
    keys = []
    values = {}
    if not path.exists():
        return keys, values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if k not in values:
            keys.append(k)
        values[k] = v
    return keys, values

template_keys, template_values = parse_env(template_path)
env_keys, env_values = parse_env(env_path)

out_lines = []
out_lines.append(f"# Auto-synced from {template_path.name} (mode={mode})")
out_lines.append("# Existing .env values override template defaults.")
out_lines.append("")

written = set()
for key in template_keys:
    value = env_values.get(key, template_values[key])
    out_lines.append(f"{key}={value}")
    written.add(key)

extra_keys = [k for k in env_keys if k not in written]
if extra_keys:
    out_lines.append("")
    out_lines.append("# Extra keys preserved from previous .env")
    for key in extra_keys:
        out_lines.append(f"{key}={env_values[key]}")

env_path.write_text("\n".join(out_lines).rstrip() + "\n", encoding="utf-8")
PY

chmod 600 .env
log "Synced .env from ${TEMPLATE} (mode=${MODE})."
