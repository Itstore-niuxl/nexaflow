# NexaFlow

NexaFlow is a v0.1 traffic analysis PoC focused on the core path:

```text
mock packets -> 5s aggregation -> Redis / ClickHouse -> Go API -> Vue dashboard
```

## Current Scope

- Go collector with mock traffic generation.
- 5 second window aggregation.
- ClickHouse writes through HTTP.
- Redis realtime TopN writes through RESP.
- Go API for summary, timeseries, TopN, health.
- Vue 3 dashboard.

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
./scripts/sync_to_server.sh
./scripts/server_compose.sh up --build -d
./scripts/list_server_interfaces.sh
```

The web console can switch the collector mode and interface from the `采集器` page. The same operation is available from the command line:

```bash
./scripts/set_capture_interface.sh eth0 live_pcap
./scripts/set_capture_interface.sh any live_pcap
```

The current live mode uses Linux `AF_PACKET` raw socket capture and writes 5-second windows to ClickHouse.
