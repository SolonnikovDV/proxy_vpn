#!/usr/bin/env bash
# Write current release metadata for UI consumption.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_PATH="${RELEASE_STATE_FILE:-logs/app-release-state.json}"
mkdir -p "$(dirname "${OUT_PATH}")"

short_sha="$(git rev-parse --short HEAD 2>/dev/null || echo na)"
full_sha="$(git rev-parse HEAD 2>/dev/null || echo na)"
content="$(git show "HEAD:RELEASE_NOTES.md" 2>/dev/null || true)"

version="${short_sha}"
notes="No release notes available."
if [ -n "${content}" ]; then
  parsed_version="$(printf '%s\n' "${content}" | awk '/^## /{sub(/^## /, "", $0); print; exit}')"
  if [ -n "${parsed_version}" ]; then
    version="${parsed_version}"
  fi
  parsed_notes="$(
    printf '%s\n' "${content}" | awk '
    BEGIN { capture=0; out=""; n=0 }
    /^## / {
      if (capture==0) { capture=1; next }
      else { exit }
    }
    capture==1 {
      if (n < 12) {
        if (length(out) > 0) out = out " "
        out = out $0
        n++
      }
    }
    END { print out }'
  )"
  if [ -n "${parsed_notes}" ]; then
    notes="${parsed_notes}"
  fi
fi

python3 - "${OUT_PATH}" "${version}" "${full_sha}" "${short_sha}" "${notes}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
full_sha = sys.argv[3]
short_sha = sys.argv[4]
notes = sys.argv[5]

state = {
    "current": {
        "version": version or "unknown",
        "sha": full_sha or "na",
        "build": short_sha or "",
        "notes": notes or "No release notes available.",
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    },
    "available": None,
    "update": {
        "status": "idle",
        "message": "Release metadata refreshed from repository.",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    },
}

if path.exists():
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(existing, dict):
            state["available"] = existing.get("available")
            upd = existing.get("update")
            if isinstance(upd, dict):
                # Keep update status history, only refresh timestamp/message if missing.
                state["update"].update(upd)
                state["update"]["updated_at"] = datetime.now(timezone.utc).isoformat()
    except Exception:
        pass

path.write_text(json.dumps(state, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
PY

echo "Release metadata written to ${OUT_PATH}: version=${version}, build=${short_sha}"
