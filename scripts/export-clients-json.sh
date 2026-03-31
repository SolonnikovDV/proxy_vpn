#!/usr/bin/env bash
# Export merged client data (WireGuard + Xray) to JSON.
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

OUTPUT_PATH="${OUTPUT_PATH:-exports/clients-export.json}"
WG_DIR="${WG_DIR:-wireguard/conf}"
XRAY_DIR="${XRAY_DIR:-xray/clients}"

[ -d "${WG_DIR}" ] || die "WG directory not found: ${WG_DIR}"
[ -d "${XRAY_DIR}" ] || die "Xray clients directory not found: ${XRAY_DIR}"

mkdir -p "$(dirname "${OUTPUT_PATH}")"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

python3 - "${WG_DIR}" "${XRAY_DIR}" "${tmp}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

wg_dir = Path(sys.argv[1])
xray_dir = Path(sys.argv[2])
tmp_path = Path(sys.argv[3])

clients = []

for wg_file in sorted(wg_dir.glob("*.conf")):
    name = wg_file.stem
    if name == "wg0":
        continue

    text = wg_file.read_text(encoding="utf-8", errors="replace")

    def pick(pattern: str) -> str:
        m = re.search(pattern, text, re.MULTILINE)
        return m.group(1).strip() if m else ""

    wg_address = pick(r"^Address\s*=\s*(.+)$")
    wg_endpoint = pick(r"^Endpoint\s*=\s*(.+)$")

    xray_file = xray_dir / f"{name}.txt"
    xray_uuid = ""
    xray_uri = ""
    if xray_file.exists():
        xtext = xray_file.read_text(encoding="utf-8", errors="replace")
        m_uuid = re.search(r"^UUID:\s*(.+)$", xtext, re.MULTILINE)
        if m_uuid:
            xray_uuid = m_uuid.group(1).strip()
        m_uri = re.search(r"^(vless://.+)$", xtext, re.MULTILINE)
        if m_uri:
            xray_uri = m_uri.group(1).strip()

    clients.append(
        {
            "name": name,
            "wireguard": {
                "config_path": str(wg_file),
                "address": wg_address,
                "endpoint": wg_endpoint,
            },
            "xray": {
                "client_file": str(xray_file),
                "uuid": xray_uuid,
                "uri": xray_uri,
            },
        }
    )

if not clients:
    raise SystemExit(f"No client .conf files found in {wg_dir}")

payload = {"clients": clients, "count": len(clients)}
tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

mv "${tmp}" "${OUTPUT_PATH}"
chmod 600 "${OUTPUT_PATH}"
log "JSON exported: ${OUTPUT_PATH}"
