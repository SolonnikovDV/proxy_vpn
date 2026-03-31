#!/usr/bin/env bash
# Login to server using env-provided SSH credentials.
set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

SSH_HOST="${SSH_HOST:-}"
SSH_USER="${SSH_USER:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
SSH_PORT="${SSH_PORT:-22}"

[ -n "${SSH_HOST}" ] || die "SSH_HOST is required"
[ -n "${SSH_USER}" ] || die "SSH_USER is required"

if [ -n "${SSH_PASSWORD}" ]; then
  command -v sshpass >/dev/null 2>&1 || die "sshpass is required for password auth"
  if [ "$#" -gt 0 ]; then
    sshpass -p "${SSH_PASSWORD}" ssh \
      -o StrictHostKeyChecking=accept-new \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -p "${SSH_PORT}" \
      "${SSH_USER}@${SSH_HOST}" "$@"
  else
    sshpass -p "${SSH_PASSWORD}" ssh \
      -o StrictHostKeyChecking=accept-new \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -p "${SSH_PORT}" \
      "${SSH_USER}@${SSH_HOST}"
  fi
  exit 0
fi

if [ "$#" -gt 0 ]; then
  ssh -o StrictHostKeyChecking=accept-new -p "${SSH_PORT}" "${SSH_USER}@${SSH_HOST}" "$@"
else
  ssh -o StrictHostKeyChecking=accept-new -p "${SSH_PORT}" "${SSH_USER}@${SSH_HOST}"
fi
