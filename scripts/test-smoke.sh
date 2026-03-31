#!/usr/bin/env bash
# Run API smoke tests in local virtualenv (one command).
set -euo pipefail
cd "$(dirname "$0")/.."

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

if ! command -v python3 >/dev/null 2>&1; then
  die "python3 not found. Install Python 3.9+ first."
fi

if [ ! -d ".venv" ]; then
  log "Creating virtualenv: .venv"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

log "Installing dev dependencies..."
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements-dev.txt

log "Running smoke tests..."
pytest -q tests/test_smoke.py "$@"
