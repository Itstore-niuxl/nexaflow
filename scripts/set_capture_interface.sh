#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <interface> [mode]"
  echo "Example: $0 eth0 live_pcap"
  exit 1
fi

IFACE="$1"
MODE="${2:-live_pcap}"
REMOTE_HOST="${NEXAFLOW_REMOTE_HOST:?Set NEXAFLOW_REMOTE_HOST to your Ubuntu server host}"
REMOTE_USER="${NEXAFLOW_REMOTE_USER:-ubuntu}"
REMOTE_DIR="${NEXAFLOW_REMOTE_DIR:-/home/ubuntu/nexaflow}"
SSH_KEY="${NEXAFLOW_SSH_KEY:-$HOME/.ssh/nexaflow_ubuntu}"

ssh -i "${SSH_KEY}" "${REMOTE_USER}@${REMOTE_HOST}" "
  set -euo pipefail
  test -e /sys/class/net/${IFACE}
  cd '${REMOTE_DIR}'
  cat > .env <<EOF
NEXAFLOW_MODE=${MODE}
NEXAFLOW_IFACE=${IFACE}
NEXAFLOW_SOURCE_ID=${MODE}-${IFACE}
NEXAFLOW_BPF_FILTER=ip or ip6
EOF
  mkdir -p runtime
  cat > runtime/collector_config.json <<EOF
{
  "mode": "${MODE}",
  "iface": "${IFACE}",
  "source_id": "${MODE}-${IFACE}",
  "bpf_filter": "ip or ip6",
  "updated_at": $(date +%s)
}
EOF
  docker compose -f deploy/docker-compose.yaml up --build -d api-server collector web
  docker compose -f deploy/docker-compose.yaml exec -T clickhouse clickhouse-client --user default --password nexaflow --query 'TRUNCATE TABLE IF EXISTS nexaflow.link_traffic_5s'
  docker compose -f deploy/docker-compose.yaml exec -T clickhouse clickhouse-client --user default --password nexaflow --query 'TRUNCATE TABLE IF EXISTS nexaflow.ip_traffic_5s'
  docker compose -f deploy/docker-compose.yaml exec -T clickhouse clickhouse-client --user default --password nexaflow --query 'TRUNCATE TABLE IF EXISTS nexaflow.dimension_traffic_5s'
  docker compose -f deploy/docker-compose.yaml ps collector api-server web
"

echo "采集模式已切换：${MODE} / ${IFACE}"
