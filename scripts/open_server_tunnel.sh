#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${NEXAFLOW_REMOTE_HOST:?Set NEXAFLOW_REMOTE_HOST to your Ubuntu server host}"
REMOTE_USER="${NEXAFLOW_REMOTE_USER:-ubuntu}"
SSH_KEY="${NEXAFLOW_SSH_KEY:-$HOME/.ssh/nexaflow_ubuntu}"
LOCAL_PORT="${NEXAFLOW_TUNNEL_PORT:-18081}"

echo "Open http://localhost:${LOCAL_PORT}"
ssh -i "${SSH_KEY}" -N -L "${LOCAL_PORT}:127.0.0.1:80" "${REMOTE_USER}@${REMOTE_HOST}"
