#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${NEXAFLOW_REMOTE_HOST:?Set NEXAFLOW_REMOTE_HOST to your Ubuntu server host}"
REMOTE_USER="${NEXAFLOW_REMOTE_USER:-ubuntu}"
REMOTE_DIR="${NEXAFLOW_REMOTE_DIR:-/home/ubuntu/nexaflow}"
SSH_KEY="${NEXAFLOW_SSH_KEY:-$HOME/.ssh/nexaflow_ubuntu}"

ssh -i "${SSH_KEY}" "${REMOTE_USER}@${REMOTE_HOST}" \
  "cd '${REMOTE_DIR}' && docker compose -f deploy/docker-compose.yaml ${*:-ps}"
