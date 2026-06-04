#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${NEXAFLOW_REMOTE_HOST:?Set NEXAFLOW_REMOTE_HOST to your Ubuntu server host}"
REMOTE_USER="${NEXAFLOW_REMOTE_USER:-ubuntu}"
SSH_KEY="${NEXAFLOW_SSH_KEY:-$HOME/.ssh/nexaflow_ubuntu}"

ssh -i "${SSH_KEY}" "${REMOTE_USER}@${REMOTE_HOST}" '
  echo "可用网卡："
  ip -o link show | awk -F": " "{print \$2}" | sed "s/@.*//" | while read -r iface; do
    state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo unknown)
    printf "  %-18s %s\n" "${iface}" "${state}"
  done
  echo
  echo "tcpdump 可采集接口："
  sudo -n tcpdump -D 2>/dev/null || true
'
