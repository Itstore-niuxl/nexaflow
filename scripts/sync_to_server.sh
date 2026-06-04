#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_HOST="${NEXAFLOW_REMOTE_HOST:?Set NEXAFLOW_REMOTE_HOST to your Ubuntu server host}"
REMOTE_USER="${NEXAFLOW_REMOTE_USER:-ubuntu}"
REMOTE_DIR="${NEXAFLOW_REMOTE_DIR:-/home/ubuntu/nexaflow}"
SSH_KEY="${NEXAFLOW_SSH_KEY:-$HOME/.ssh/nexaflow_ubuntu}"

rsync -az --delete \
  --exclude '.git' \
  --exclude 'runtime' \
  --exclude 'web/node_modules' \
  --exclude 'web/dist' \
  -e "ssh -i ${SSH_KEY}" \
  "${ROOT_DIR}/" \
  "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

echo "Synced to ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"
