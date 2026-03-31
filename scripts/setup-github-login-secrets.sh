#!/usr/bin/env bash
# Backward-compatible wrapper. Prefer scripts/setup-github-config.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

SSH_HOST="${SSH_HOST:-}"
SSH_USER="${SSH_USER:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"

[ -n "${SSH_HOST}" ] || { printf 'ERROR: SSH_HOST is required\n' >&2; exit 1; }
[ -n "${SSH_USER}" ] || { printf 'ERROR: SSH_USER is required\n' >&2; exit 1; }
[ -n "${SSH_PASSWORD}" ] || { printf 'ERROR: SSH_PASSWORD is required\n' >&2; exit 1; }

SSH_HOST="${SSH_HOST}" \
SSH_USER="${SSH_USER}" \
SSH_PASSWORD="${SSH_PASSWORD}" \
bash ./scripts/setup-github-config.sh
