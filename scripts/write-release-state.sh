#!/usr/bin/env bash
# Write current release metadata for UI consumption.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT_PATH="${RELEASE_STATE_FILE:-logs/app-release-state.json}"
mkdir -p "$(dirname "${OUT_PATH}")"

python3 - "${OUT_PATH}" <<'PY'
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
repo = Path.cwd()

def parse_release_notes(text: str):
    version = ""
    notes = ""
    m = re.search(r"(?m)^##\s+(.+?)\s*$", text or "")
    if m:
        version = m.group(1).strip()
    sec = re.search(r"(?ms)^##\s+[^\n]+\n(.*?)(?:\n##\s+|\Z)", text or "")
    if sec:
        body = (sec.group(1) or "").strip()
        if body:
            notes = " ".join(line.strip() for line in body.splitlines() if line.strip())[:1600]
    return version, notes

def infer_sha_from_logs() -> str:
    candidates = []
    upd = repo / "logs" / "update-audit.jsonl"
    if upd.exists():
        try:
            for raw in upd.read_text(encoding="utf-8").splitlines()[-500:]:
                line = (raw or "").strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict):
                    to_sha = str(item.get("to", "") or "").strip()
                    if to_sha and to_sha.lower() != "na":
                        candidates.append(to_sha)
        except Exception:
            pass
    dep = repo / "logs" / "deploy-history.log"
    if dep.exists():
        try:
            for raw in dep.read_text(encoding="utf-8").splitlines()[-500:]:
                m = re.search(r"(?:^|\|)to=([0-9a-fA-F]{7,40}|na)(?:\||$)", raw or "")
                if m:
                    to_sha = (m.group(1) or "").strip()
                    if to_sha and to_sha.lower() != "na":
                        candidates.append(to_sha)
        except Exception:
            pass
    return candidates[-1] if candidates else ""

def infer_build_from_docker() -> str:
    try:
        image_id = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Image}}", "proxy-vpn-api"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return ""
    if image_id.startswith("sha256:"):
        image_id = image_id.split(":", 1)[1]
    return (image_id or "").strip()[:12]

existing = {}
if path.exists():
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(obj, dict):
            existing = obj
    except Exception:
        existing = {}

version = ""
notes = ""
full_sha = ""
short_sha = ""

try:
    full_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), stderr=subprocess.DEVNULL, text=True).strip()
    short_sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=str(repo), stderr=subprocess.DEVNULL, text=True).strip()
except Exception:
    full_sha = ""
    short_sha = ""

notes_path = repo / "RELEASE_NOTES.md"
if notes_path.exists():
    try:
        raw_notes = notes_path.read_text(encoding="utf-8")
        version, notes = parse_release_notes(raw_notes)
    except Exception:
        pass

if not full_sha:
    full_sha = infer_sha_from_logs()
if full_sha and not short_sha:
    short_sha = full_sha[:7]
if not short_sha:
    short_sha = infer_build_from_docker()

cur_existing = existing.get("current") if isinstance(existing.get("current"), dict) else {}
version = version or str(cur_existing.get("version", "") or "")
notes = notes or str(cur_existing.get("notes", "") or "")
full_sha = full_sha or str(cur_existing.get("sha", "") or "")
short_sha = short_sha or str(cur_existing.get("build", "") or "")

if not version or version.lower() in {"na", "unknown"}:
    version = short_sha or "unknown"
if not notes:
    notes = "No release notes available."
if not full_sha:
    full_sha = "unknown"
if not short_sha:
    short_sha = "unknown"

state = {
    "current": {
        "version": version,
        "sha": full_sha,
        "build": short_sha,
        "notes": notes,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    },
    "available": None,
    "update": {
        "status": "idle",
        "message": "Release metadata refreshed from repository.",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    },
}

if isinstance(existing, dict):
    state["available"] = existing.get("available")
    upd = existing.get("update")
    if isinstance(upd, dict):
        state["update"].update(upd)
        state["update"]["updated_at"] = datetime.now(timezone.utc).isoformat()

path.write_text(json.dumps(state, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
print(f"Release metadata written to {path}: version={version}, build={short_sha}")
PY
