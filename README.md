# NexaFlow

NexaFlow is a v0.1 traffic analysis PoC focused on the core path:

```text
mock / pcap replay / live NIC -> 5s aggregation -> Redis / ClickHouse -> Go API -> Vue console
```

## Current Scope

- Go collector with mock traffic generation, classic pcap replay, and Linux live NIC capture.
- 5 second window aggregation with configurable session and pair retention per window.
- 1 minute ClickHouse rollup tables and materialized views.
- ClickHouse writes through HTTP.
- Redis realtime TopN writes through RESP.
- Go API for summary, timeseries, TopN, object drilldown trends, service recognition dimensions, VLAN/QoS dimensions, profiles, assets, alerts, health, and `/metrics`.
- Vue 3 console with live monitoring, traffic analysis, service recognition, service exposure, QoS insights, asset inventory, alerts, search, history, and collector controls.
- Collector online/offline health is inferred from the latest 5 second window.

## Local Development

Go and Docker are required for the backend runtime. The current machine must install them before running the full stack.

```bash
docker compose -f deploy/docker-compose.yaml up --build
```

Then open:

```text
http://localhost:8081
```

Frontend-only development:

```bash
cd web
npm install
npm run dev
```

## Remote Validation

The Ubuntu validation server is driven from local scripts:

```bash
NEXAFLOW_REMOTE_HOST=<ubuntu-ip> ./scripts/sync_to_server.sh
NEXAFLOW_REMOTE_HOST=<ubuntu-ip> ./scripts/server_compose.sh up --build -d
NEXAFLOW_REMOTE_HOST=<ubuntu-ip> ./scripts/list_server_interfaces.sh
```

Console login is optional. Set `NEXAFLOW_AUTH_PASSWORD` in the server `.env` and restart `api-server`/`web` to protect `/api/v1/*` with a signed HttpOnly session cookie:

```bash
NEXAFLOW_AUTH_PASSWORD='<strong-password>'
NEXAFLOW_AUTH_READONLY_PASSWORD='<viewer-password>'
NEXAFLOW_AUTH_SECRET='<random-session-secret>'
```

`NEXAFLOW_AUTH_PASSWORD` grants administrator access. `NEXAFLOW_AUTH_READONLY_PASSWORD` grants observer access: dashboards and queries are available, but write operations such as collector switching, rule changes, alert handling, whitelist updates, asset metadata edits, and incident notes are rejected.

AI summaries are available in local deterministic mode by default. Set `NEXAFLOW_AI_MODE=disabled` to hide AI summaries, or configure an OpenAI-compatible provider through `NEXAFLOW_AI_PROVIDER`, `NEXAFLOW_AI_MODEL`, `NEXAFLOW_AI_BASE_URL`, and `NEXAFLOW_AI_API_KEY`. External providers are called through `<base_url>/chat/completions` for incident, asset, and report summaries; if the provider fails, NexaFlow falls back to the local summary and marks the response as degraded.

Configuration changes are recorded in the `配置版本` page. Administrators can restore a previous runtime configuration snapshot from that page; restore actions are also audited and versioned.

The web console can switch the collector mode and interface from the `采集器` page. The same operation is available from the command line:

```bash
./scripts/set_capture_interface.sh eth0 live_pcap
./scripts/set_capture_interface.sh any live_pcap
```

The current live mode uses Linux `AF_PACKET` raw socket capture and writes 5-second windows to ClickHouse.

PCAP replay expects a classic Ethernet `.pcap` file inside the runtime volume, for example:

```bash
scp sample.pcap ubuntu@<ubuntu-ip>:/home/ubuntu/nexaflow/runtime/replay.pcap
```

Then switch the collector from the Web `采集器` page or post:

```bash
curl -X POST http://<ubuntu-ip>:8081/api/v1/collectors/config \
  -H 'Content-Type: application/json' \
  -d '{"mode":"pcap_replay","iface":"replay0","source_id":"pcap-replay0","bpf_filter":"ip or ip6","pcap_file":"/var/lib/nexaflow/replay.pcap","replay_speed":5,"session_topn":500}'
```

Prometheus-style metrics are available at:

```text
http://<ubuntu-ip>:8081/metrics
```
