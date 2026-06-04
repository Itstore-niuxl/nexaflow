package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"nexaflow/internal/model"
)

type Store struct {
	baseURL  string
	database string
	client   *http.Client
}

func New(baseURL, database string) *Store {
	return &Store{
		baseURL:  strings.TrimRight(baseURL, "/"),
		database: database,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *Store) Init(ctx context.Context) error {
	queries := []string{
		"CREATE DATABASE IF NOT EXISTS " + s.database,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.link_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    bytes UInt64,
    packets UInt64,
    drops UInt64,
    utilization Float64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, iface, ts)
TTL ts + INTERVAL 7 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.ip_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    ip String,
    direction LowCardinality(String),
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, direction, ts, ip)
TTL ts + INTERVAL 7 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.dimension_traffic_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    dimension LowCardinality(String),
    dim_key String,
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, dimension, ts, dim_key)
TTL ts + INTERVAL 7 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.link_traffic_1m
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    bytes UInt64,
    packets UInt64,
    drops UInt64,
    utilization Float64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, iface, ts)
TTL ts + INTERVAL 30 DAY`,
		`CREATE MATERIALIZED VIEW IF NOT EXISTS ` + s.database + `.mv_link_traffic_1m
TO ` + s.database + `.link_traffic_1m
AS SELECT
    toStartOfMinute(ts) AS ts,
    source_id,
    iface,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(drops) AS drops,
    max(utilization) AS utilization
FROM ` + s.database + `.link_traffic_5s
GROUP BY ts, source_id, iface`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.ip_traffic_1m
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    ip String,
    direction LowCardinality(String),
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, direction, ts, ip)
TTL ts + INTERVAL 30 DAY`,
		`CREATE MATERIALIZED VIEW IF NOT EXISTS ` + s.database + `.mv_ip_traffic_1m
TO ` + s.database + `.ip_traffic_1m
AS SELECT
    toStartOfMinute(ts) AS ts,
    source_id,
    iface,
    ip,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM ` + s.database + `.ip_traffic_5s
GROUP BY ts, source_id, iface, ip, direction`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.dimension_traffic_1m
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    dimension LowCardinality(String),
    dim_key String,
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, dimension, ts, dim_key)
TTL ts + INTERVAL 30 DAY`,
		`CREATE MATERIALIZED VIEW IF NOT EXISTS ` + s.database + `.mv_dimension_traffic_1m
TO ` + s.database + `.dimension_traffic_1m
AS SELECT
    toStartOfMinute(ts) AS ts,
    source_id,
    iface,
    dimension,
    dim_key,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM ` + s.database + `.dimension_traffic_5s
GROUP BY ts, source_id, iface, dimension, dim_key`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.alert_events
(
    id String,
    severity LowCardinality(String),
    status LowCardinality(String),
    subject String,
    summary String,
    first_seen DateTime,
    last_seen DateTime
)
ENGINE = MergeTree
PARTITION BY toDate(first_seen)
ORDER BY (severity, status, first_seen, id)
TTL first_seen + INTERVAL 180 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.alert_status_overrides
(
    id String,
    status LowCardinality(String),
    updated_at DateTime
)
ENGINE = MergeTree
PARTITION BY toDate(updated_at)
ORDER BY (id, updated_at)
TTL updated_at + INTERVAL 180 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.asset_metadata_overrides
(
    ip String,
    name String,
    owner String,
    business String,
    environment LowCardinality(String),
    criticality LowCardinality(String),
    tags String,
    note String,
    updated_at DateTime
)
ENGINE = MergeTree
PARTITION BY toDate(updated_at)
ORDER BY (ip, updated_at)
TTL updated_at + INTERVAL 365 DAY`,
	}
	for _, q := range queries {
		if err := s.exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) WaitInit(ctx context.Context, attempts int, delay time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		if err := s.Init(ctx); err != nil {
			last = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			continue
		}
		return nil
	}
	return last
}

func (s *Store) WriteWindow(ctx context.Context, win model.WindowResult) error {
	if err := s.insertLink(ctx, win.Link); err != nil {
		return err
	}
	if err := s.insertIP(ctx, win.SourceID, win.Iface, win.Ts, "src", win.TopSrcIP); err != nil {
		return err
	}
	if err := s.insertIP(ctx, win.SourceID, win.Iface, win.Ts, "dst", win.TopDstIP); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "dst_port", win.TopDstPort); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "protocol", win.TopProtocol); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "flow", win.TopFlow); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "pair", win.TopPair); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "packet_len", win.TopPacketLen); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "service", win.TopService); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "service_category", win.TopSvcCat); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "service_risk", win.TopSvcRisk); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "vlan", win.TopVLAN); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "dscp", win.TopDSCP); err != nil {
		return err
	}
	if err := s.insertDim(ctx, win.SourceID, win.Iface, win.Ts, "ecn", win.TopECN); err != nil {
		return err
	}
	for _, alert := range win.Alerts {
		if err := s.insertAlert(ctx, alert); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Summary(ctx context.Context, minutes int) (map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    ifNull(sum(bytes), 0) AS bytes,
    ifNull(sum(packets), 0) AS packets,
    ifNull(max(utilization), 0) AS utilization
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoSummary(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Data) == 0 {
		return demoSummary(), err
	}
	return parsed.Data[0], nil
}

func (s *Store) TopN(ctx context.Context, dimension, direction string, limit, minutes int) ([]model.TopItem, error) {
	var q string
	if dimension == "ip" {
		q = fmt.Sprintf(`SELECT ip AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND direction = '%s'
GROUP BY ip
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, escape(direction), limit)
	} else {
		q = fmt.Sprintf(`SELECT dim_key AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = '%s'
GROUP BY dim_key
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, escape(dimension), limit)
	}
	body, err := s.query(ctx, q)
	if err != nil {
		return demoTopN(dimension), err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoTopN(dimension), err
	}
	return parsed.Data, nil
}

func (s *Store) Timeseries(ctx context.Context, minutes int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT toUnixTimestamp(ts) AS ts, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
GROUP BY ts
ORDER BY ts ASC
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoSeries(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoSeries(), err
	}
	return parsed.Data, nil
}

func (s *Store) Status(ctx context.Context) (map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    ifNull(max(toUnixTimestamp(ts)), 0) AS latest_window_ts,
    count() AS windows_24h,
    uniqExact(source_id) AS sources_24h,
    uniqExact(iface) AS interfaces_24h
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL 24 HOUR
FORMAT JSON`, s.database)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoStatus(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Data) == 0 {
		return demoStatus(), err
	}
	parsed.Data[0]["database"] = "ok"
	return parsed.Data[0], nil
}

func (s *Store) Alerts(ctx context.Context, limit, minutes int) ([]model.AlertEvent, error) {
	q := fmt.Sprintf(`SELECT
    e.id AS id,
    e.severity AS severity,
    if(o.id = '', e.status, o.status) AS status,
    e.subject AS subject,
    e.summary AS summary,
    toUnixTimestamp(e.first_seen) AS first_seen,
    toUnixTimestamp(e.last_seen) AS last_seen
FROM %s.alert_events AS e
LEFT JOIN (
    SELECT id, argMax(status, updated_at) AS status
    FROM %s.alert_status_overrides
    GROUP BY id
) AS o ON e.id = o.id
WHERE e.last_seen >= now() - INTERVAL %d MINUTE
ORDER BY last_seen DESC
LIMIT %d
FORMAT JSON`, s.database, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoAlerts(), err
	}
	var parsed struct {
		Data []model.AlertEvent `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoAlerts(), err
	}
	return parsed.Data, nil
}

func (s *Store) UpdateAlertStatus(ctx context.Context, id, status string) error {
	if id == "" {
		return fmt.Errorf("alert id is required")
	}
	if status != "open" && status != "ack" && status != "resolved" {
		return fmt.Errorf("unsupported alert status %q", status)
	}
	q := "INSERT INTO " + s.database + ".alert_status_overrides FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"id":%q,"status":%q,"updated_at":%q}`+"\n", id, status, formatTime(time.Now().Unix())))
}

func (s *Store) IPProfile(ctx context.Context, ip string, minutes int) (map[string]any, error) {
	stats, err := s.ipStats(ctx, ip, minutes)
	if err != nil {
		return demoIPProfile(ip), err
	}
	pairs, pairErr := s.dimensionLike(ctx, "pair", ip, minutes, 10)
	flows, flowErr := s.dimensionLike(ctx, "flow", ip, minutes, 10)
	lastSeen, lastSeenErr := s.ipLastSeen(ctx, ip, minutes)
	profile := map[string]any{
		"ip":               ip,
		"minutes":          minutes,
		"inbound_bytes":    stats["dst"].Bytes,
		"inbound_packets":  stats["dst"].Packets,
		"outbound_bytes":   stats["src"].Bytes,
		"outbound_packets": stats["src"].Packets,
		"top_pairs":        pairs,
		"top_flows":        flows,
		"last_seen":        lastSeen,
	}
	if pairErr != nil || flowErr != nil || lastSeenErr != nil {
		return profile, firstErr(pairErr, flowErr, lastSeenErr)
	}
	return profile, nil
}

func (s *Store) PortProfile(ctx context.Context, port string, minutes int) (map[string]any, error) {
	stats, err := s.portStats(ctx, port, minutes)
	if err != nil {
		return demoPortProfile(port), err
	}
	flows, flowErr := s.dimensionLike(ctx, "flow", ":"+port+" /", minutes, 10)
	profile := map[string]any{
		"port":    port,
		"minutes": minutes,
		"bytes":   stats.Bytes,
		"packets": stats.Packets,
		"flows":   flows,
	}
	if flowErr != nil {
		return profile, flowErr
	}
	return profile, nil
}

func (s *Store) Windows(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS window_ts,
    source_id,
    iface,
    bytes,
    packets,
    utilization
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
ORDER BY ts DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoWindows(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoWindows(), err
	}
	return parsed.Data, nil
}

func (s *Store) Matrix(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	items, err := s.TopN(ctx, "pair", "src", limit, minutes)
	if err != nil {
		return demoMatrix(), err
	}
	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		src, dst := splitPair(item.Key)
		rows = append(rows, map[string]any{
			"src":     src,
			"dst":     dst,
			"bytes":   item.Bytes,
			"packets": item.Packets,
		})
	}
	return rows, nil
}

func (s *Store) ServiceMap(ctx context.Context, minutes, limit int) (map[string]any, error) {
	links, err := s.Matrix(ctx, minutes, limit)
	if err != nil {
		return demoServiceMap(), err
	}
	nodes := map[string]map[string]any{}
	for _, link := range links {
		src := stringValue(link["src"])
		dst := stringValue(link["dst"])
		bytes := uintValue(link["bytes"])
		packets := uintValue(link["packets"])
		addNode(nodes, src, bytes, packets)
		addNode(nodes, dst, bytes, packets)
	}
	nodeRows := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		nodeRows = append(nodeRows, node)
	}
	return map[string]any{"nodes": nodeRows, "links": links}, nil
}

func (s *Store) ProtocolTimeseries(ctx context.Context, minutes int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS ts,
    dim_key AS protocol,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'protocol'
GROUP BY ts, protocol
ORDER BY ts ASC, protocol ASC
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoProtocolSeries(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoProtocolSeries(), err
	}
	return parsed.Data, nil
}

func (s *Store) PortTimeseries(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS ts,
    dim_key AS port,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND dimension = 'dst_port'
    AND dim_key IN (
        SELECT dim_key
        FROM %s.dimension_traffic_5s
        WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'dst_port'
        GROUP BY dim_key
        ORDER BY sum(bytes) DESC
        LIMIT %d
    )
GROUP BY ts, port
ORDER BY ts ASC, port ASC
FORMAT JSON`, s.database, minutes, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoPortSeries(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoPortSeries(), err
	}
	return parsed.Data, nil
}

func (s *Store) DirectionTimeseries(ctx context.Context, minutes int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS ts,
    dim_key AS pair,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'pair'
GROUP BY ts, pair
ORDER BY ts ASC
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoDirectionSeries(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoDirectionSeries(), err
	}
	grouped := map[string]map[string]any{}
	for _, row := range parsed.Data {
		ts := int64(floatValue(row["ts"]))
		src, dst := splitPair(stringValue(row["pair"]))
		direction := directionLabel(src, dst)
		key := strconv.FormatInt(ts, 10) + "|" + direction
		item := grouped[key]
		if item == nil {
			item = map[string]any{"ts": ts, "direction": direction, "bytes": uint64(0), "packets": uint64(0)}
		}
		item["bytes"] = uintValue(item["bytes"]) + uintValue(row["bytes"])
		item["packets"] = uintValue(item["packets"]) + uintValue(row["packets"])
		grouped[key] = item
	}
	items := make([]map[string]any, 0, len(grouped))
	for _, item := range grouped {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if floatValue(items[i]["ts"]) == floatValue(items[j]["ts"]) {
			return stringValue(items[i]["direction"]) < stringValue(items[j]["direction"])
		}
		return floatValue(items[i]["ts"]) < floatValue(items[j]["ts"])
	})
	return items, nil
}

func (s *Store) DimensionTimeseries(ctx context.Context, dimension, key, direction string, minutes, limit int) ([]map[string]any, error) {
	dimension = strings.TrimSpace(dimension)
	key = strings.TrimSpace(key)
	if dimension == "" {
		dimension = "service"
	}
	var q string
	if dimension == "ip" {
		if direction == "" {
			direction = "src"
		}
		whereKey := ""
		if key != "" {
			whereKey = " AND ip = '" + escape(key) + "'"
		} else {
			whereKey = fmt.Sprintf(` AND ip IN (
        SELECT ip
        FROM %s.ip_traffic_5s
        WHERE ts >= now() - INTERVAL %d MINUTE AND direction = '%s'
        GROUP BY ip
        ORDER BY sum(bytes) DESC
        LIMIT %d
    )`, s.database, minutes, escape(direction), limit)
		}
		q = fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS ts,
    'ip' AS dimension,
    ip AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND direction = '%s'%s
GROUP BY ts, key
ORDER BY ts ASC, key ASC
FORMAT JSON`, s.database, minutes, escape(direction), whereKey)
	} else {
		whereKey := ""
		if key != "" {
			whereKey = " AND dim_key = '" + escape(key) + "'"
		} else {
			whereKey = fmt.Sprintf(` AND dim_key IN (
        SELECT dim_key
        FROM %s.dimension_traffic_5s
        WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = '%s'
        GROUP BY dim_key
        ORDER BY sum(bytes) DESC
        LIMIT %d
    )`, s.database, minutes, escape(dimension), limit)
		}
		q = fmt.Sprintf(`SELECT
    toUnixTimestamp(ts) AS ts,
    dimension AS dimension,
    dim_key AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = '%s'%s
GROUP BY ts, dimension, key
ORDER BY ts ASC, key ASC
FORMAT JSON`, s.database, minutes, escape(dimension), whereKey)
	}
	body, err := s.query(ctx, q)
	if err != nil {
		return demoDimensionSeries(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoDimensionSeries(), err
	}
	return parsed.Data, nil
}

func (s *Store) ObjectRelations(ctx context.Context, dimension, key, direction string, minutes, limit int) (map[string]any, error) {
	dimension = strings.TrimSpace(dimension)
	key = strings.TrimSpace(key)
	direction = strings.TrimSpace(direction)
	if dimension == "" {
		dimension = "service"
	}
	if limit <= 0 {
		limit = 8
	}
	summary, summaryErr := s.objectRelationSummary(ctx, dimension, key, direction, minutes)
	flows, flowErr := s.objectRelationFlows(ctx, dimension, key, minutes, limit)
	relatedIPs, relatedPorts, relatedServices := aggregateFlowRelations(dimension, key, flows, limit)
	insights, insightErr := s.relatedSecurityInsights(ctx, dimension, key, minutes, limit)
	summary["related_count"] = len(flows)
	return map[string]any{
		"dimension":        dimension,
		"key":              key,
		"direction":        direction,
		"minutes":          minutes,
		"summary":          summary,
		"related_ips":      relatedIPs,
		"related_ports":    relatedPorts,
		"related_services": relatedServices,
		"related_flows":    flows,
		"insights":         insights,
	}, firstErr(summaryErr, flowErr, insightErr)
}

func (s *Store) objectRelationSummary(ctx context.Context, dimension, key, direction string, minutes int) (map[string]any, error) {
	label := key
	if label == "" {
		label = "全部对象"
	}
	var q string
	if dimension == "ip" {
		where := ""
		if key != "" {
			where += " AND ip = '" + escape(key) + "'"
		}
		if direction == "src" || direction == "dst" {
			where += " AND direction = '" + escape(direction) + "'"
		}
		q = fmt.Sprintf(`SELECT '%s' AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE%s
FORMAT JSON`, escape(label), s.database, minutes, where)
	} else {
		where := ""
		if key != "" {
			where = " AND dim_key = '" + escape(key) + "'"
		}
		q = fmt.Sprintf(`SELECT '%s' AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = '%s'%s
FORMAT JSON`, escape(label), s.database, minutes, escape(dimension), where)
	}
	body, err := s.query(ctx, q)
	if err != nil {
		return relationSummary(label, 0, 0), err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return relationSummary(label, 0, 0), err
	}
	if len(parsed.Data) == 0 {
		return relationSummary(label, 0, 0), nil
	}
	return relationSummary(label, parsed.Data[0].Bytes, parsed.Data[0].Packets), nil
}

func (s *Store) objectRelationFlows(ctx context.Context, dimension, key string, minutes, limit int) ([]model.TopItem, error) {
	if key == "" {
		return s.TopN(ctx, "flow", "src", limit, minutes)
	}
	switch dimension {
	case "ip":
		return s.dimensionLike(ctx, "flow", key, minutes, limit)
	case "flow":
		return s.dimensionLike(ctx, "flow", key, minutes, limit)
	case "pair":
		left, right := splitPair(key)
		candidates, err := s.dimensionLike(ctx, "flow", left, minutes, limit*4)
		if err != nil {
			return nil, err
		}
		filtered := make([]model.TopItem, 0, limit)
		for _, flow := range candidates {
			if right == "" || strings.Contains(flow.Key, right) {
				filtered = append(filtered, flow)
			}
			if len(filtered) >= limit {
				break
			}
		}
		return filtered, nil
	case "dst_port":
		return s.dimensionLike(ctx, "flow", ":"+key+" /", minutes, limit)
	case "protocol":
		return s.dimensionLike(ctx, "flow", " / "+key, minutes, limit)
	case "service", "service_category", "service_risk":
		return s.flowsForServiceSelector(ctx, dimension, key, minutes, limit)
	default:
		return []model.TopItem{}, nil
	}
}

func (s *Store) flowsForServiceSelector(ctx context.Context, dimension, key string, minutes, limit int) ([]model.TopItem, error) {
	ports := portsForServiceSelector(dimension, key)
	merged := map[string]model.TopItem{}
	var first error
	for _, port := range ports {
		rows, err := s.dimensionLike(ctx, "flow", ":"+port+" /", minutes, limit)
		if err != nil && first == nil {
			first = err
		}
		for _, row := range rows {
			parsed, ok := parseFlowKey(row.Key)
			if !ok || parsed.DstPort != port {
				continue
			}
			addTopItem(merged, row.Key, row.Bytes, row.Packets)
		}
	}
	return sortedTopItems(merged, limit), first
}

func (s *Store) relatedSecurityInsights(ctx context.Context, dimension, key string, minutes, limit int) ([]map[string]any, error) {
	items, err := s.SecurityInsights(ctx, minutes, max(limit*5, 30))
	if key == "" {
		if len(items) > limit {
			items = items[:limit]
		}
		return items, err
	}
	markers := []string{key, dimension + ":" + key}
	if dimension == "dst_port" {
		markers = append(markers, ":"+key+" ", ":"+key+" /")
	}
	if dimension == "protocol" {
		markers = append(markers, " / "+key)
	}
	filtered := make([]map[string]any, 0, limit)
	for _, item := range items {
		text := stringValue(item["subject"]) + " " + stringValue(item["summary"])
		for _, marker := range markers {
			if marker != "" && strings.Contains(text, marker) {
				filtered = append(filtered, item)
				break
			}
		}
		if len(filtered) >= limit {
			break
		}
	}
	return filtered, err
}

func (s *Store) Sessions(ctx context.Context, q string, minutes, limit int) ([]map[string]any, error) {
	where := ""
	if q = strings.TrimSpace(q); q != "" {
		where = " AND position(dim_key, '" + escape(q) + "') > 0"
	}
	query := fmt.Sprintf(`SELECT
    dim_key AS key,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    min(toUnixTimestamp(ts)) AS first_seen,
    max(toUnixTimestamp(ts)) AS last_seen
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'flow'%s
GROUP BY key
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, where, limit)
	body, err := s.query(ctx, query)
	if err != nil {
		return demoSessions(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoSessions(), err
	}
	rows := make([]map[string]any, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		item := model.TopItem{
			Key:     stringValue(row["key"]),
			Bytes:   uintValue(row["bytes"]),
			Packets: uintValue(row["packets"]),
		}
		rows = append(rows, sessionRow(item, int64Value(row["first_seen"]), int64Value(row["last_seen"])))
	}
	return rows, nil
}

func (s *Store) Search(ctx context.Context, q string, minutes, limit int) ([]map[string]any, error) {
	if q == "" {
		return []map[string]any{}, nil
	}
	escaped := escape(q)
	query := fmt.Sprintf(`SELECT * FROM (
    SELECT concat('ip:', direction) AS kind, ip AS key, sum(bytes) AS bytes, sum(packets) AS packets
    FROM %s.ip_traffic_5s
    WHERE ts >= now() - INTERVAL %d MINUTE AND position(ip, '%s') > 0
    GROUP BY kind, key
    UNION ALL
    SELECT dimension AS kind, dim_key AS key, sum(bytes) AS bytes, sum(packets) AS packets
    FROM %s.dimension_traffic_5s
    WHERE ts >= now() - INTERVAL %d MINUTE AND position(dim_key, '%s') > 0
    GROUP BY kind, key
)
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, escaped, s.database, minutes, escaped, limit)
	body, err := s.query(ctx, query)
	if err != nil {
		return demoSearch(q), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoSearch(q), err
	}
	return parsed.Data, nil
}

func (s *Store) TrafficAnalysis(ctx context.Context, minutes int) (map[string]any, error) {
	baseline, baselineErr := s.trafficBaseline(ctx, minutes)
	protocols, protocolErr := s.TopN(ctx, "protocol", "src", 8, minutes)
	ports, portErr := s.TopN(ctx, "dst_port", "src", 12, minutes)
	packetLens, packetLenErr := s.TopN(ctx, "packet_len", "src", 10, minutes)
	matrix, matrixErr := s.Matrix(ctx, minutes, 500)
	directions := directionDistribution(matrix)
	analysis := map[string]any{
		"minutes":      minutes,
		"baseline":     baseline,
		"protocol_mix": protocols,
		"port_mix":     ports,
		"packet_sizes": packetLens,
		"directions":   directions,
	}
	if baselineErr != nil && protocolErr != nil && portErr != nil && packetLenErr != nil && matrixErr != nil {
		return demoTrafficAnalysis(), firstErr(baselineErr, protocolErr, portErr, packetLenErr, matrixErr)
	}
	return analysis, firstErr(baselineErr, protocolErr, portErr, packetLenErr, matrixErr)
}

func (s *Store) TrafficChanges(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	srcChanges, srcErr := s.dimensionChanges(ctx, "src_ip", "ip", "src", minutes, limit)
	dstChanges, dstErr := s.dimensionChanges(ctx, "dst_ip", "ip", "dst", minutes, limit)
	portChanges, portErr := s.dimensionChanges(ctx, "dst_port", "dst_port", "src", minutes, limit)
	protoChanges, protoErr := s.dimensionChanges(ctx, "protocol", "protocol", "src", minutes, limit)
	changes := append(srcChanges, dstChanges...)
	changes = append(changes, portChanges...)
	changes = append(changes, protoChanges...)
	sort.Slice(changes, func(i, j int) bool {
		return int64Value(changes[i]["delta_bytes"]) > int64Value(changes[j]["delta_bytes"])
	})
	if len(changes) > limit {
		changes = changes[:limit]
	}
	if len(changes) == 0 && (srcErr != nil || dstErr != nil || portErr != nil || protoErr != nil) {
		return demoTrafficChanges(), firstErr(srcErr, dstErr, portErr, protoErr)
	}
	return changes, firstErr(srcErr, dstErr, portErr, protoErr)
}

func (s *Store) ServiceExposure(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	flows, err := s.TopN(ctx, "flow", "src", limit*5, minutes)
	if err != nil {
		return demoServiceExposure(), err
	}
	grouped := map[string]map[string]any{}
	clients := map[string]map[string]bool{}
	for _, flow := range flows {
		parsed, ok := parseFlowKey(flow.Key)
		if !ok {
			continue
		}
		exposure, ok := inferExposureEndpoint(parsed)
		if !ok {
			continue
		}
		service := identifyService(exposure.Port, parsed.Proto)
		key := exposure.IP + "|" + exposure.Port + "|" + parsed.Proto
		row := grouped[key]
		if row == nil {
			row = map[string]any{
				"ip":            exposure.IP,
				"port":          exposure.Port,
				"protocol":      parsed.Proto,
				"service":       service.Name,
				"category":      service.Category,
				"risk":          service.Risk,
				"direction":     exposure.Direction,
				"confidence":    exposure.Confidence,
				"bytes":         uint64(0),
				"packets":       uint64(0),
				"client_count":  uint64(0),
				"sample_client": exposure.ClientIP,
				"sample_flow":   flow.Key,
			}
			clients[key] = map[string]bool{}
		}
		row["bytes"] = uintValue(row["bytes"]) + flow.Bytes
		row["packets"] = uintValue(row["packets"]) + flow.Packets
		clients[key][exposure.ClientIP] = true
		row["client_count"] = uint64(len(clients[key]))
		grouped[key] = row
	}
	rows := make([]map[string]any, 0, len(grouped))
	for _, row := range grouped {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if riskWeight(stringValue(rows[i]["risk"])) != riskWeight(stringValue(rows[j]["risk"])) {
			return riskWeight(stringValue(rows[i]["risk"])) > riskWeight(stringValue(rows[j]["risk"]))
		}
		return uintValue(rows[i]["bytes"]) > uintValue(rows[j]["bytes"])
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *Store) ExternalAccess(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	sessions, err := s.Sessions(ctx, "", minutes, limit*8)
	if err != nil {
		return demoExternalAccess(), err
	}
	grouped := map[string]map[string]any{}
	for _, session := range sessions {
		row, ok := externalAccessRow(session)
		if !ok {
			continue
		}
		key := strings.Join([]string{
			stringValue(row["public_ip"]),
			stringValue(row["internal_ip"]),
			stringValue(row["port"]),
			stringValue(row["protocol"]),
			stringValue(row["direction"]),
		}, "|")
		current := grouped[key]
		if current == nil {
			current = row
			current["bytes"] = uint64(0)
			current["packets"] = uint64(0)
			current["session_count"] = uint64(0)
			current["first_seen"] = int64Value(session["first_seen"])
			current["last_seen"] = int64Value(session["last_seen"])
		}
		current["bytes"] = uintValue(current["bytes"]) + uintValue(session["bytes"])
		current["packets"] = uintValue(current["packets"]) + uintValue(session["packets"])
		current["session_count"] = uintValue(current["session_count"]) + 1
		if first := int64Value(session["first_seen"]); first > 0 && (int64Value(current["first_seen"]) == 0 || first < int64Value(current["first_seen"])) {
			current["first_seen"] = first
		}
		if last := int64Value(session["last_seen"]); last > int64Value(current["last_seen"]) {
			current["last_seen"] = last
			current["sample_flow"] = stringValue(session["key"])
		}
		grouped[key] = current
	}
	rows := make([]map[string]any, 0, len(grouped))
	for _, row := range grouped {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if riskWeight(stringValue(rows[i]["risk"])) != riskWeight(stringValue(rows[j]["risk"])) {
			return riskWeight(stringValue(rows[i]["risk"])) > riskWeight(stringValue(rows[j]["risk"]))
		}
		if uintValue(rows[i]["session_count"]) != uintValue(rows[j]["session_count"]) {
			return uintValue(rows[i]["session_count"]) > uintValue(rows[j]["session_count"])
		}
		return uintValue(rows[i]["bytes"]) > uintValue(rows[j]["bytes"])
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *Store) Assets(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    ip,
    sumIf(bytes, direction = 'dst') AS inbound_bytes,
    sumIf(packets, direction = 'dst') AS inbound_packets,
    sumIf(bytes, direction = 'src') AS outbound_bytes,
    sumIf(packets, direction = 'src') AS outbound_packets,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    toUnixTimestamp(min(ts)) AS first_seen,
    toUnixTimestamp(max(ts)) AS last_seen
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
GROUP BY ip
ORDER BY total_bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoAssets(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoAssets(), err
	}
	for _, row := range parsed.Data {
		row["role"] = assetRole(uintValue(row["inbound_bytes"]), uintValue(row["outbound_bytes"]))
		row["avg_packet_size"] = averagePacketSize(uintValue(row["total_bytes"]), uintValue(row["total_packets"]))
	}
	metadata, metaErr := s.AssetMetadata(ctx, "")
	if metaErr == nil {
		for _, row := range parsed.Data {
			if item, ok := metadata[stringValue(row["ip"])]; ok {
				mergeAssetMetadata(row, item)
			} else {
				mergeAssetMetadata(row, map[string]any{})
			}
		}
	} else {
		for _, row := range parsed.Data {
			mergeAssetMetadata(row, map[string]any{})
		}
	}
	return parsed.Data, nil
}

func (s *Store) AssetMetadata(ctx context.Context, ip string) (map[string]map[string]any, error) {
	where := ""
	if strings.TrimSpace(ip) != "" {
		where = "WHERE ip = '" + escape(strings.TrimSpace(ip)) + "'"
	}
	q := fmt.Sprintf(`SELECT
    ip,
    argMax(name, updated_at) AS name,
    argMax(owner, updated_at) AS owner,
    argMax(business, updated_at) AS business,
    argMax(environment, updated_at) AS environment,
    argMax(criticality, updated_at) AS criticality,
    argMax(tags, updated_at) AS tags,
    argMax(note, updated_at) AS note,
    toUnixTimestamp(max(updated_at)) AS metadata_updated_at
FROM %s.asset_metadata_overrides
%s
GROUP BY ip
FORMAT JSON`, s.database, where)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	result := map[string]map[string]any{}
	for _, row := range parsed.Data {
		normalizeAssetMetadata(row)
		result[stringValue(row["ip"])] = row
	}
	return result, nil
}

func (s *Store) UpdateAssetMetadata(ctx context.Context, row map[string]any) (map[string]any, error) {
	ip := strings.TrimSpace(stringValue(row["ip"]))
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	metadata := map[string]any{
		"ip":          ip,
		"name":        strings.TrimSpace(stringValue(row["name"])),
		"owner":       strings.TrimSpace(stringValue(row["owner"])),
		"business":    strings.TrimSpace(stringValue(row["business"])),
		"environment": strings.TrimSpace(stringValue(row["environment"])),
		"criticality": strings.TrimSpace(stringValue(row["criticality"])),
		"tags":        normalizeTagString(row["tags"]),
		"note":        strings.TrimSpace(stringValue(row["note"])),
	}
	if metadata["environment"] == "" {
		metadata["environment"] = "未分类"
	}
	if metadata["criticality"] == "" {
		metadata["criticality"] = "normal"
	}
	q := "INSERT INTO " + s.database + ".asset_metadata_overrides FORMAT JSONEachRow"
	if err := s.execBody(ctx, q, fmt.Sprintf(`{"ip":%q,"name":%q,"owner":%q,"business":%q,"environment":%q,"criticality":%q,"tags":%q,"note":%q,"updated_at":%q}`+"\n",
		ip,
		stringValue(metadata["name"]),
		stringValue(metadata["owner"]),
		stringValue(metadata["business"]),
		stringValue(metadata["environment"]),
		stringValue(metadata["criticality"]),
		stringValue(metadata["tags"]),
		stringValue(metadata["note"]),
		formatTime(time.Now().Unix()),
	)); err != nil {
		return nil, err
	}
	metadata["metadata_updated_at"] = time.Now().Unix()
	normalizeAssetMetadata(metadata)
	return metadata, nil
}

func (s *Store) SecurityInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	totalBytes, totalErr := s.totalLinkBytes(ctx, minutes)
	flows, flowErr := s.TopN(ctx, "flow", "src", limit, minutes)
	fanouts, fanoutErr := s.fanoutInsights(ctx, minutes, limit)
	ports, portErr := s.sensitivePortInsights(ctx, minutes, limit)
	serviceRisks, serviceRiskErr := s.serviceRiskInsights(ctx, minutes, limit)
	qosMarks, qosErr := s.qosInsights(ctx, minutes, limit)

	items := make([]map[string]any, 0, len(flows)+len(fanouts)+len(ports)+len(serviceRisks)+len(qosMarks))
	for _, flow := range flows {
		if len(items) >= limit {
			break
		}
		share := 0.0
		if totalBytes > 0 {
			share = float64(flow.Bytes) / float64(totalBytes)
		}
		if flow.Bytes < 10*1024*1024 && share < 0.15 {
			continue
		}
		severity := "warning"
		if share >= 0.4 {
			severity = "critical"
		}
		items = append(items, map[string]any{
			"kind":     "heavy_flow",
			"severity": severity,
			"subject":  flow.Key,
			"summary":  fmt.Sprintf("单会话占近 %d 分钟总流量 %.1f%%", minutes, share*100),
			"bytes":    flow.Bytes,
			"packets":  flow.Packets,
			"score":    int(share * 100),
		})
	}
	items = append(items, fanouts...)
	items = append(items, ports...)
	items = append(items, serviceRisks...)
	items = append(items, qosMarks...)
	sort.Slice(items, func(i, j int) bool {
		if insightWeight(stringValue(items[i]["severity"])) != insightWeight(stringValue(items[j]["severity"])) {
			return insightWeight(stringValue(items[i]["severity"])) > insightWeight(stringValue(items[j]["severity"]))
		}
		return uintValue(items[i]["bytes"]) > uintValue(items[j]["bytes"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	if len(items) == 0 && (totalErr != nil || flowErr != nil || fanoutErr != nil || portErr != nil || serviceRiskErr != nil || qosErr != nil) {
		return demoSecurityInsights(), firstErr(totalErr, flowErr, fanoutErr, portErr, serviceRiskErr, qosErr)
	}
	return items, firstErr(totalErr, flowErr, fanoutErr, portErr, serviceRiskErr, qosErr)
}

func (s *Store) ipStats(ctx context.Context, ip string, minutes int) (map[string]model.TopItem, error) {
	q := fmt.Sprintf(`SELECT direction AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND ip = '%s'
GROUP BY direction
FORMAT JSON`, s.database, minutes, escape(ip))
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	result := map[string]model.TopItem{
		"src": {Key: "src"},
		"dst": {Key: "dst"},
	}
	for _, row := range parsed.Data {
		result[row.Key] = row
	}
	return result, nil
}

func (s *Store) portStats(ctx context.Context, port string, minutes int) (model.TopItem, error) {
	q := fmt.Sprintf(`SELECT dim_key AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'dst_port' AND dim_key = '%s'
GROUP BY dim_key
FORMAT JSON`, s.database, minutes, escape(port))
	body, err := s.query(ctx, q)
	if err != nil {
		return model.TopItem{}, err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return model.TopItem{}, err
	}
	if len(parsed.Data) == 0 {
		return model.TopItem{Key: port}, nil
	}
	return parsed.Data[0], nil
}

func (s *Store) dimensionLike(ctx context.Context, dimension, value string, minutes, limit int) ([]model.TopItem, error) {
	q := fmt.Sprintf(`SELECT dim_key AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = '%s' AND position(dim_key, '%s') > 0
GROUP BY dim_key
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, escape(dimension), escape(value), limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return parsed.Data, nil
}

func (s *Store) dimensionChanges(ctx context.Context, label, dimension, direction string, minutes, limit int) ([]map[string]any, error) {
	current, currentErr := s.topNWindow(ctx, dimension, direction, 0, minutes, limit)
	previous, previousErr := s.topNWindow(ctx, dimension, direction, minutes, minutes*2, limit*2)
	previousByKey := map[string]model.TopItem{}
	for _, item := range previous {
		previousByKey[item.Key] = item
	}
	rows := make([]map[string]any, 0, len(current))
	for _, item := range current {
		prev := previousByKey[item.Key]
		deltaBytes := int64(item.Bytes) - int64(prev.Bytes)
		deltaPackets := int64(item.Packets) - int64(prev.Packets)
		rows = append(rows, map[string]any{
			"dimension":        label,
			"key":              item.Key,
			"current_bytes":    item.Bytes,
			"previous_bytes":   prev.Bytes,
			"delta_bytes":      deltaBytes,
			"current_packets":  item.Packets,
			"previous_packets": prev.Packets,
			"delta_packets":    deltaPackets,
			"change_ratio":     changeRatio(item.Bytes, prev.Bytes),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return int64Value(rows[i]["delta_bytes"]) > int64Value(rows[j]["delta_bytes"])
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, firstErr(currentErr, previousErr)
}

func (s *Store) topNWindow(ctx context.Context, dimension, direction string, startMinutesAgo, endMinutesAgo, limit int) ([]model.TopItem, error) {
	var q string
	if dimension == "ip" {
		q = fmt.Sprintf(`SELECT ip AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND ts < now() - INTERVAL %d MINUTE
    AND direction = '%s'
GROUP BY ip
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, endMinutesAgo, startMinutesAgo, escape(direction), limit)
	} else {
		q = fmt.Sprintf(`SELECT dim_key AS key, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND ts < now() - INTERVAL %d MINUTE
    AND dimension = '%s'
GROUP BY dim_key
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, endMinutesAgo, startMinutesAgo, escape(dimension), limit)
	}
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return parsed.Data, nil
}

func (s *Store) trafficBaseline(ctx context.Context, minutes int) (map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    count() AS windows,
    ifNull(avg(bytes), 0) AS avg_bytes,
    ifNull(max(bytes), 0) AS peak_bytes,
    ifNull(quantileExact(0.95)(bytes), 0) AS p95_bytes,
    ifNull(avg(packets), 0) AS avg_packets,
    ifNull(max(packets), 0) AS peak_packets,
    ifNull(avg(utilization), 0) AS avg_utilization,
    ifNull(max(utilization), 0) AS peak_utilization
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Data) == 0 {
		return nil, err
	}
	row := parsed.Data[0]
	avgBytes := floatValue(row["avg_bytes"])
	peakBytes := floatValue(row["peak_bytes"])
	p95Bytes := floatValue(row["p95_bytes"])
	row["avg_mbps"] = bytesToMbps(avgBytes, 5)
	row["peak_mbps"] = bytesToMbps(peakBytes, 5)
	row["p95_mbps"] = bytesToMbps(p95Bytes, 5)
	row["burst_ratio"] = ratio(peakBytes, avgBytes)
	return row, nil
}

func (s *Store) totalLinkBytes(ctx context.Context, minutes int) (uint64, error) {
	q := fmt.Sprintf(`SELECT ifNull(sum(bytes), 0) AS bytes
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Data) == 0 {
		return 0, err
	}
	return uintValue(parsed.Data[0]["bytes"]), nil
}

func (s *Store) fanoutInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    arrayElement(splitByString(' -> ', dim_key), 1) AS src,
    uniqExact(arrayElement(splitByString(' -> ', dim_key), 2)) AS dst_count,
    sum(bytes) AS bytes,
    sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND dimension = 'pair' AND position(dim_key, ' -> ') > 0
GROUP BY src
HAVING dst_count >= 3
ORDER BY dst_count DESC, bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		dstCount := uintValue(row["dst_count"])
		severity := "warning"
		if dstCount >= 20 {
			severity = "critical"
		}
		items = append(items, map[string]any{
			"kind":     "fanout",
			"severity": severity,
			"subject":  row["src"],
			"summary":  fmt.Sprintf("源主机在 %d 分钟内访问 %d 个目的主机", minutes, dstCount),
			"bytes":    row["bytes"],
			"packets":  row["packets"],
			"score":    int(dstCount),
		})
	}
	return items, nil
}

func (s *Store) sensitivePortInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT dim_key AS port, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND dimension = 'dst_port'
    AND dim_key IN ('22','23','445','139','3389','3306','5432','6379','9200','11211','27017')
GROUP BY port
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		items = append(items, map[string]any{
			"kind":     "sensitive_port",
			"severity": "warning",
			"subject":  "dst_port:" + stringValue(row["port"]),
			"summary":  "发现敏感服务端口访问流量",
			"bytes":    row["bytes"],
			"packets":  row["packets"],
			"score":    70,
		})
	}
	return items, nil
}

func (s *Store) serviceRiskInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT dim_key AS risk, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND dimension = 'service_risk'
    AND dim_key IN ('critical','high')
GROUP BY risk
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		risk := stringValue(row["risk"])
		severity := "warning"
		score := 75
		if risk == "critical" {
			severity = "critical"
			score = 90
		}
		items = append(items, map[string]any{
			"kind":     "service_risk",
			"severity": severity,
			"subject":  "service_risk:" + risk,
			"summary":  "发现高风险服务类型流量",
			"bytes":    row["bytes"],
			"packets":  row["packets"],
			"score":    score,
		})
	}
	return items, nil
}

func (s *Store) qosInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	ecnItems, ecnErr := s.qosDimensionInsights(ctx, "ecn", []string{"CE", "ECT(0)", "ECT(1)"}, "ecn_mark", "发现 ECN 拥塞/可拥塞传输标记", minutes, limit)
	dscpItems, dscpErr := s.qosDimensionInsights(ctx, "dscp", []string{"EF", "AF11", "AF12", "AF13", "AF21", "AF22", "AF23", "AF31", "AF32", "AF33", "AF41", "AF42", "AF43", "CS5", "CS6", "CS7"}, "qos_mark", "发现非默认 DSCP/QoS 标记流量", minutes, limit)
	items := append(ecnItems, dscpItems...)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, firstErr(ecnErr, dscpErr)
}

func (s *Store) qosDimensionInsights(ctx context.Context, dimension string, keys []string, kind, summary string, minutes, limit int) ([]map[string]any, error) {
	quoted := make([]string, 0, len(keys))
	for _, key := range keys {
		quoted = append(quoted, "'"+escape(key)+"'")
	}
	q := fmt.Sprintf(`SELECT dim_key AS mark, sum(bytes) AS bytes, sum(packets) AS packets
FROM %s.dimension_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND dimension = '%s'
    AND dim_key IN (%s)
GROUP BY mark
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, escape(dimension), strings.Join(quoted, ","), limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		mark := stringValue(row["mark"])
		severity := "info"
		score := 45
		if mark == "CE" || mark == "EF" || mark == "CS6" || mark == "CS7" {
			severity = "warning"
			score = 65
		}
		items = append(items, map[string]any{
			"kind":     kind,
			"severity": severity,
			"subject":  dimension + ":" + mark,
			"summary":  summary,
			"bytes":    row["bytes"],
			"packets":  row["packets"],
			"score":    score,
		})
	}
	return items, nil
}

func (s *Store) ipLastSeen(ctx context.Context, ip string, minutes int) (int64, error) {
	q := fmt.Sprintf(`SELECT ifNull(max(toUnixTimestamp(ts)), 0) AS last_seen
FROM %s.ip_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE AND ip = '%s'
FORMAT JSON`, s.database, minutes, escape(ip))
	body, err := s.query(ctx, q)
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Data []map[string]int64 `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Data) == 0 {
		return 0, err
	}
	return parsed.Data[0]["last_seen"], nil
}

func (s *Store) insertLink(ctx context.Context, row model.LinkWindow) error {
	q := "INSERT INTO " + s.database + ".link_traffic_5s FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"ts":%q,"source_id":%q,"iface":%q,"bytes":%d,"packets":%d,"drops":%d,"utilization":%f}`+"\n",
		formatTime(row.Ts), row.SourceID, row.Iface, row.Bytes, row.Packets, row.Drops, row.Util))
}

func (s *Store) insertIP(ctx context.Context, sourceID, iface string, ts int64, direction string, rows []model.TopItem) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, `{"ts":%q,"source_id":%q,"iface":%q,"ip":%q,"direction":%q,"bytes":%d,"packets":%d}`+"\n",
			formatTime(ts), sourceID, iface, row.Key, direction, row.Bytes, row.Packets)
	}
	return s.execBody(ctx, "INSERT INTO "+s.database+".ip_traffic_5s FORMAT JSONEachRow", b.String())
}

func (s *Store) insertDim(ctx context.Context, sourceID, iface string, ts int64, dimension string, rows []model.TopItem) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, `{"ts":%q,"source_id":%q,"iface":%q,"dimension":%q,"dim_key":%q,"bytes":%d,"packets":%d}`+"\n",
			formatTime(ts), sourceID, iface, dimension, row.Key, row.Bytes, row.Packets)
	}
	return s.execBody(ctx, "INSERT INTO "+s.database+".dimension_traffic_5s FORMAT JSONEachRow", b.String())
}

func (s *Store) insertAlert(ctx context.Context, row model.AlertEvent) error {
	q := "INSERT INTO " + s.database + ".alert_events FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"id":%q,"severity":%q,"status":%q,"subject":%q,"summary":%q,"first_seen":%q,"last_seen":%q}`+"\n",
		row.ID, row.Severity, row.Status, row.Subject, row.Summary, formatTime(row.FirstSeen), formatTime(row.LastSeen)))
}

func (s *Store) exec(ctx context.Context, q string) error {
	return s.execBody(ctx, q, "")
}

func (s *Store) execBody(ctx context.Context, q, body string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/?query="+url.QueryEscape(q), bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse status=%d body=%s", resp.StatusCode, string(data))
	}
	return nil
}

func (s *Store) query(ctx context.Context, q string) ([]byte, error) {
	endpoint := s.baseURL + "/?output_format_json_quote_64bit_integers=0&query=" + url.QueryEscape(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse status=%d body=%s", resp.StatusCode, string(data))
	}
	return data, nil
}

func formatTime(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05")
}

func escape(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}

func demoSummary() map[string]any {
	return map[string]any{"bytes": 125829120, "packets": 94281, "utilization": 0.18}
}

func demoStatus() map[string]any {
	return map[string]any{
		"database":         "degraded",
		"latest_window_ts": time.Now().Unix(),
		"windows_24h":      0,
		"sources_24h":      0,
		"interfaces_24h":   0,
	}
}

func demoIPProfile(ip string) map[string]any {
	if ip == "" {
		ip = "10.10.1.42"
	}
	return map[string]any{
		"ip":               ip,
		"minutes":          15,
		"inbound_bytes":    uint64(52000000),
		"inbound_packets":  uint64(18000),
		"outbound_bytes":   uint64(68000000),
		"outbound_packets": uint64(21000),
		"top_pairs": []model.TopItem{
			{Key: ip + " -> 172.20.2.10", Bytes: 42000000, Packets: 14000},
			{Key: "172.20.2.81 -> " + ip, Bytes: 18000000, Packets: 7200},
		},
		"top_flows": []model.TopItem{
			{Key: ip + ":53210 -> 172.20.2.10:443 / tcp", Bytes: 42000000, Packets: 14000},
			{Key: ip + ":49812 -> 172.20.2.144:53 / udp", Bytes: 5000000, Packets: 12000},
		},
		"last_seen": time.Now().Unix(),
	}
}

func demoPortProfile(port string) map[string]any {
	if port == "" {
		port = "443"
	}
	return map[string]any{
		"port":    port,
		"minutes": 15,
		"bytes":   uint64(88000000),
		"packets": uint64(48000),
		"flows": []model.TopItem{
			{Key: "10.10.1.42:53210 -> 172.20.2.10:" + port + " / tcp", Bytes: 42000000, Packets: 14000},
			{Key: "10.10.1.77:53192 -> 172.20.2.81:" + port + " / tcp", Bytes: 18000000, Packets: 7200},
		},
	}
}

func demoWindows() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{"window_ts": now - 5, "source_id": "dev-source-01", "iface": "mock0", "bytes": 54000000, "packets": 12000, "utilization": 0.02},
		{"window_ts": now - 10, "source_id": "dev-source-01", "iface": "mock0", "bytes": 48000000, "packets": 11000, "utilization": 0.018},
	}
}

func demoMatrix() []map[string]any {
	return []map[string]any{
		{"src": "10.10.1.42", "dst": "172.20.2.10", "bytes": uint64(52000000), "packets": uint64(18000)},
		{"src": "10.10.1.77", "dst": "172.20.2.81", "bytes": uint64(21000000), "packets": uint64(8000)},
	}
}

func demoServiceMap() map[string]any {
	return map[string]any{
		"nodes": []map[string]any{
			{"ip": "10.10.1.42", "bytes": uint64(52000000), "packets": uint64(18000)},
			{"ip": "172.20.2.10", "bytes": uint64(52000000), "packets": uint64(18000)},
		},
		"links": demoMatrix(),
	}
}

func demoProtocolSeries() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{"ts": now - 10, "protocol": "tcp", "bytes": uint64(42000000), "packets": uint64(14000)},
		{"ts": now - 10, "protocol": "udp", "bytes": uint64(5000000), "packets": uint64(12000)},
	}
}

func demoPortSeries() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{"ts": now - 10, "port": "443", "bytes": uint64(42000000), "packets": uint64(14000)},
		{"ts": now - 10, "port": "80", "bytes": uint64(18000000), "packets": uint64(7200)},
	}
}

func demoDirectionSeries() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{"ts": now - 10, "direction": "出站", "bytes": uint64(76000000), "packets": uint64(48000)},
		{"ts": now - 10, "direction": "内网东西向", "bytes": uint64(26000000), "packets": uint64(22000)},
	}
}

func demoDimensionSeries() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{"ts": now - 120, "dimension": "service", "key": "HTTPS", "bytes": uint64(18000000), "packets": uint64(7200)},
		{"ts": now - 60, "dimension": "service", "key": "HTTPS", "bytes": uint64(24000000), "packets": uint64(9300)},
		{"ts": now, "dimension": "service", "key": "HTTPS", "bytes": uint64(42000000), "packets": uint64(14000)},
	}
}

func demoSearch(q string) []map[string]any {
	return []map[string]any{
		{"kind": "flow", "key": q + ":53210 -> 172.20.2.10:443 / tcp", "bytes": uint64(42000000), "packets": uint64(14000)},
		{"kind": "pair", "key": q + " -> 172.20.2.10", "bytes": uint64(52000000), "packets": uint64(18000)},
	}
}

func demoSessions() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		sessionRow(model.TopItem{Key: "10.10.1.42:53210 -> 172.20.2.10:443 / tcp", Bytes: 42000000, Packets: 14000}, now-180, now),
		sessionRow(model.TopItem{Key: "10.10.1.77:53192 -> 172.20.2.81:22 / tcp", Bytes: 18000000, Packets: 7200}, now-120, now-10),
		sessionRow(model.TopItem{Key: "10.10.1.18:49812 -> 172.20.2.144:53 / udp", Bytes: 5000000, Packets: 12000}, now-90, now-5),
	}
}

func demoTrafficChanges() []map[string]any {
	return []map[string]any{
		{
			"dimension":        "src_ip",
			"key":              "10.10.1.42",
			"current_bytes":    uint64(68000000),
			"previous_bytes":   uint64(22000000),
			"delta_bytes":      int64(46000000),
			"current_packets":  uint64(21000),
			"previous_packets": uint64(9000),
			"delta_packets":    int64(12000),
			"change_ratio":     2.09,
		},
		{
			"dimension":        "dst_port",
			"key":              "443",
			"current_bytes":    uint64(88000000),
			"previous_bytes":   uint64(52000000),
			"delta_bytes":      int64(36000000),
			"current_packets":  uint64(48000),
			"previous_packets": uint64(31000),
			"delta_packets":    int64(17000),
			"change_ratio":     0.69,
		},
	}
}

func demoServiceExposure() []map[string]any {
	return []map[string]any{
		{
			"ip":            "172.20.2.10",
			"port":          "443",
			"protocol":      "tcp",
			"service":       "HTTPS",
			"category":      "Web",
			"risk":          "low",
			"direction":     "入站",
			"confidence":    "高",
			"bytes":         uint64(42000000),
			"packets":       uint64(14000),
			"client_count":  uint64(3),
			"sample_client": "10.10.1.42",
			"sample_flow":   "10.10.1.42:53210 -> 172.20.2.10:443 / tcp",
		},
		{
			"ip":            "172.20.2.81",
			"port":          "22",
			"protocol":      "tcp",
			"service":       "SSH",
			"category":      "远程管理",
			"risk":          "high",
			"direction":     "入站",
			"confidence":    "高",
			"bytes":         uint64(18000000),
			"packets":       uint64(7200),
			"client_count":  uint64(2),
			"sample_client": "10.10.1.77",
			"sample_flow":   "10.10.1.77:53192 -> 172.20.2.81:22 / tcp",
		},
	}
}

func demoAssets() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{
			"ip":                  "10.10.1.42",
			"name":                "",
			"owner":               "",
			"business":            "",
			"environment":         "未分类",
			"criticality":         "normal",
			"tags":                []string{},
			"note":                "",
			"metadata_updated_at": int64(0),
			"role":                "外联源",
			"inbound_bytes":       uint64(12000000),
			"inbound_packets":     uint64(4000),
			"outbound_bytes":      uint64(68000000),
			"outbound_packets":    uint64(21000),
			"total_bytes":         uint64(80000000),
			"total_packets":       uint64(25000),
			"avg_packet_size":     uint64(3200),
			"first_seen":          now - 900,
			"last_seen":           now,
		},
		{
			"ip":                  "172.20.2.10",
			"name":                "示例 Web 服务",
			"owner":               "平台团队",
			"business":            "NexaFlow",
			"environment":         "测试",
			"criticality":         "high",
			"tags":                []string{"web"},
			"note":                "",
			"metadata_updated_at": now,
			"role":                "服务端",
			"inbound_bytes":       uint64(52000000),
			"inbound_packets":     uint64(18000),
			"outbound_bytes":      uint64(9000000),
			"outbound_packets":    uint64(2600),
			"total_bytes":         uint64(61000000),
			"total_packets":       uint64(20600),
			"avg_packet_size":     uint64(2961),
			"first_seen":          now - 900,
			"last_seen":           now,
		},
	}
}

func demoExternalAccess() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{
			"public_ip":     "211.93.22.130",
			"internal_ip":   "10.2.0.12",
			"direction":     "入站响应",
			"port":          "8081",
			"protocol":      "tcp",
			"service":       "HTTP Alternate",
			"category":      "Web",
			"risk":          "medium",
			"bytes":         uint64(32000000),
			"packets":       uint64(24000),
			"session_count": uint64(8),
			"sample_flow":   "10.2.0.12:8081 -> 211.93.22.130:4300 / tcp",
			"first_seen":    now - 600,
			"last_seen":     now,
		},
		{
			"public_ip":     "203.0.113.24",
			"internal_ip":   "10.2.0.12",
			"direction":     "出站",
			"port":          "443",
			"protocol":      "tcp",
			"service":       "HTTPS",
			"category":      "Web",
			"risk":          "low",
			"bytes":         uint64(12000000),
			"packets":       uint64(7800),
			"session_count": uint64(4),
			"sample_flow":   "10.2.0.12:53210 -> 203.0.113.24:443 / tcp",
			"first_seen":    now - 420,
			"last_seen":     now - 20,
		},
	}
}

func demoSecurityInsights() []map[string]any {
	return []map[string]any{
		{
			"kind":     "heavy_flow",
			"severity": "warning",
			"subject":  "10.10.1.42:53210 -> 172.20.2.10:443 / tcp",
			"summary":  "单会话占近 15 分钟总流量 32.0%",
			"bytes":    uint64(42000000),
			"packets":  uint64(14000),
			"score":    32,
		},
		{
			"kind":     "fanout",
			"severity": "warning",
			"subject":  "10.10.1.77",
			"summary":  "源主机在 15 分钟内访问 6 个目的主机",
			"bytes":    uint64(24000000),
			"packets":  uint64(9000),
			"score":    6,
		},
	}
}

func demoTrafficAnalysis() map[string]any {
	return map[string]any{
		"minutes": 15,
		"baseline": map[string]any{
			"windows":          uint64(180),
			"avg_bytes":        float64(4800000),
			"peak_bytes":       uint64(16000000),
			"p95_bytes":        uint64(12000000),
			"avg_packets":      float64(6400),
			"peak_packets":     uint64(18000),
			"avg_utilization":  0.02,
			"peak_utilization": 0.08,
			"avg_mbps":         7.68,
			"peak_mbps":        25.6,
			"p95_mbps":         19.2,
			"burst_ratio":      3.33,
		},
		"protocol_mix": []model.TopItem{
			{Key: "tcp", Bytes: 109000000, Packets: 72000},
			{Key: "udp", Bytes: 15000000, Packets: 22000},
		},
		"port_mix": []model.TopItem{
			{Key: "443", Bytes: 88000000, Packets: 48000},
			{Key: "80", Bytes: 22000000, Packets: 15000},
			{Key: "53", Bytes: 6000000, Packets: 18000},
		},
		"packet_sizes": []model.TopItem{
			{Key: "1KB-MTU", Bytes: 82000000, Packets: 56000},
			{Key: "65-128B", Bytes: 9000000, Packets: 80000},
		},
		"directions": []model.TopItem{
			{Key: "出站", Bytes: 76000000, Packets: 48000},
			{Key: "内网东西向", Bytes: 26000000, Packets: 22000},
		},
	}
}

func splitPair(key string) (string, string) {
	parts := strings.SplitN(key, " -> ", 2)
	if len(parts) != 2 {
		return key, ""
	}
	return parts[0], parts[1]
}

type parsedFlow struct {
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	Proto   string
}

func parseFlowKey(key string) (parsedFlow, bool) {
	parts := strings.SplitN(key, " / ", 2)
	if len(parts) != 2 {
		return parsedFlow{}, false
	}
	endpoints := strings.SplitN(parts[0], " -> ", 2)
	if len(endpoints) != 2 {
		return parsedFlow{}, false
	}
	srcIP, srcPort, srcOk := splitEndpoint(endpoints[0])
	dstIP, dstPort, dstOk := splitEndpoint(endpoints[1])
	if !srcOk || !dstOk {
		return parsedFlow{}, false
	}
	return parsedFlow{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   dstIP,
		DstPort: dstPort,
		Proto:   strings.TrimSpace(parts[1]),
	}, true
}

func splitEndpoint(value string) (string, string, bool) {
	index := strings.LastIndex(value, ":")
	if index <= 0 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func addNode(nodes map[string]map[string]any, ip string, bytes, packets uint64) {
	if ip == "" {
		return
	}
	node := nodes[ip]
	if node == nil {
		node = map[string]any{"ip": ip, "bytes": uint64(0), "packets": uint64(0)}
	}
	node["bytes"] = uintValue(node["bytes"]) + bytes
	node["packets"] = uintValue(node["packets"]) + packets
	nodes[ip] = node
}

func relationSummary(key string, bytes, packets uint64) map[string]any {
	return map[string]any{
		"key":           key,
		"bytes":         bytes,
		"packets":       packets,
		"related_count": 0,
	}
}

func aggregateFlowRelations(dimension, key string, flows []model.TopItem, limit int) ([]model.TopItem, []model.TopItem, []model.TopItem) {
	ips := map[string]model.TopItem{}
	ports := map[string]model.TopItem{}
	services := map[string]model.TopItem{}
	for _, flow := range flows {
		parsed, ok := parseFlowKey(flow.Key)
		if !ok {
			continue
		}
		if dimension == "ip" && key != "" {
			if parsed.SrcIP == key {
				addTopItem(ips, parsed.DstIP, flow.Bytes, flow.Packets)
			} else if parsed.DstIP == key {
				addTopItem(ips, parsed.SrcIP, flow.Bytes, flow.Packets)
			}
		} else {
			addTopItem(ips, parsed.SrcIP, flow.Bytes, flow.Packets)
			addTopItem(ips, parsed.DstIP, flow.Bytes, flow.Packets)
		}
		service := identifyService(parsed.DstPort, parsed.Proto)
		addTopItem(ports, parsed.DstPort+"/"+parsed.Proto, flow.Bytes, flow.Packets)
		addTopItem(services, service.Name, flow.Bytes, flow.Packets)
	}
	return sortedTopItems(ips, limit), sortedTopItems(ports, limit), sortedTopItems(services, limit)
}

func addTopItem(items map[string]model.TopItem, key string, bytes, packets uint64) {
	if key == "" {
		return
	}
	item := items[key]
	item.Key = key
	item.Bytes += bytes
	item.Packets += packets
	items[key] = item
}

func sortedTopItems(items map[string]model.TopItem, limit int) []model.TopItem {
	rows := make([]model.TopItem, 0, len(items))
	for _, item := range items {
		rows = append(rows, item)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes == rows[j].Bytes {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].Bytes > rows[j].Bytes
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func sessionRow(item model.TopItem, firstSeen, lastSeen int64) map[string]any {
	row := map[string]any{
		"key":             item.Key,
		"bytes":           item.Bytes,
		"packets":         item.Packets,
		"avg_packet_size": uint64(0),
		"first_seen":      firstSeen,
		"last_seen":       lastSeen,
		"src_ip":          "",
		"src_port":        "",
		"dst_ip":          "",
		"dst_port":        "",
		"protocol":        "",
		"service":         "未知服务",
		"category":        "未知",
		"risk":            "observe",
		"direction":       "未知",
		"server_ip":       "",
		"server_port":     "",
		"client_ip":       "",
		"confidence":      "低",
	}
	if item.Packets > 0 {
		row["avg_packet_size"] = item.Bytes / item.Packets
	}
	parsed, ok := parseFlowKey(item.Key)
	if !ok {
		return row
	}
	service := identifyService(parsed.DstPort, parsed.Proto)
	row["src_ip"] = parsed.SrcIP
	row["src_port"] = parsed.SrcPort
	row["dst_ip"] = parsed.DstIP
	row["dst_port"] = parsed.DstPort
	row["protocol"] = parsed.Proto
	row["service"] = service.Name
	row["category"] = service.Category
	row["risk"] = service.Risk
	row["direction"] = flowDirection(parsed)
	row["server_ip"] = parsed.DstIP
	row["server_port"] = parsed.DstPort
	row["client_ip"] = parsed.SrcIP
	if exposure, ok := inferExposureEndpoint(parsed); ok {
		row["server_ip"] = exposure.IP
		row["server_port"] = exposure.Port
		row["client_ip"] = exposure.ClientIP
		row["confidence"] = exposure.Confidence
		if exposure.Direction != "" {
			row["direction"] = exposure.Direction
		}
	}
	return row
}

func flowDirection(flow parsedFlow) string {
	srcInternal := isManagedAssetIP(flow.SrcIP)
	dstInternal := isManagedAssetIP(flow.DstIP)
	switch {
	case srcInternal && dstInternal:
		return "内网东西向"
	case srcInternal && !dstInternal:
		return "出站"
	case !srcInternal && dstInternal:
		return "入站"
	case !srcInternal && !dstInternal:
		return "外部流量"
	default:
		return "未知"
	}
}

func externalAccessRow(session map[string]any) (map[string]any, bool) {
	srcIP := stringValue(session["src_ip"])
	dstIP := stringValue(session["dst_ip"])
	serverIP := stringValue(session["server_ip"])
	serverPort := stringValue(session["server_port"])
	clientIP := stringValue(session["client_ip"])
	proto := stringValue(session["protocol"])
	direction := stringValue(session["direction"])
	publicIP := ""
	internalIP := ""
	port := serverPort
	switch {
	case serverIP != "" && clientIP != "" && isManagedAssetIP(serverIP) && !isManagedAssetIP(clientIP):
		publicIP = clientIP
		internalIP = serverIP
	case serverIP != "" && clientIP != "" && !isManagedAssetIP(serverIP) && isManagedAssetIP(clientIP):
		publicIP = serverIP
		internalIP = clientIP
		if direction == "" || direction == "未知" {
			direction = "出站"
		}
	case isManagedAssetIP(srcIP) && !isManagedAssetIP(dstIP):
		publicIP = dstIP
		internalIP = srcIP
		port = stringValue(session["dst_port"])
		direction = "出站"
	case !isManagedAssetIP(srcIP) && isManagedAssetIP(dstIP):
		publicIP = srcIP
		internalIP = dstIP
		port = stringValue(session["dst_port"])
		direction = "入站"
	default:
		return nil, false
	}
	if publicIP == "" || internalIP == "" {
		return nil, false
	}
	service := identifyService(port, proto)
	risk := service.Risk
	if stringValue(session["risk"]) != "" && port == stringValue(session["server_port"]) {
		risk = stringValue(session["risk"])
	}
	return map[string]any{
		"public_ip":     publicIP,
		"internal_ip":   internalIP,
		"direction":     direction,
		"port":          port,
		"protocol":      proto,
		"service":       service.Name,
		"category":      service.Category,
		"risk":          risk,
		"sample_flow":   stringValue(session["key"]),
		"bytes":         uint64(0),
		"packets":       uint64(0),
		"session_count": uint64(0),
		"first_seen":    int64(0),
		"last_seen":     int64(0),
	}, true
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mergeAssetMetadata(row, metadata map[string]any) {
	defaults := map[string]any{
		"name":                "",
		"owner":               "",
		"business":            "",
		"environment":         "未分类",
		"criticality":         "normal",
		"tags":                []string{},
		"note":                "",
		"metadata_updated_at": int64(0),
	}
	for key, value := range defaults {
		row[key] = value
	}
	for _, key := range []string{"name", "owner", "business", "environment", "criticality", "note"} {
		if value := strings.TrimSpace(stringValue(metadata[key])); value != "" {
			row[key] = value
		}
	}
	row["tags"] = tagsFromAny(metadata["tags"])
	if updated := int64Value(metadata["metadata_updated_at"]); updated > 0 {
		row["metadata_updated_at"] = updated
	}
}

func normalizeAssetMetadata(row map[string]any) {
	if strings.TrimSpace(stringValue(row["environment"])) == "" {
		row["environment"] = "未分类"
	}
	if strings.TrimSpace(stringValue(row["criticality"])) == "" {
		row["criticality"] = "normal"
	}
	row["tags"] = tagsFromAny(row["tags"])
}

func normalizeTagString(v any) string {
	return strings.Join(tagsFromAny(v), ",")
}

func tagsFromAny(v any) []string {
	var raw []string
	switch value := v.(type) {
	case []string:
		raw = value
	case []any:
		for _, item := range value {
			raw = append(raw, strings.TrimSpace(stringValue(item)))
		}
	case string:
		raw = strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == '，' || r == ';' || r == '；'
		})
	}
	seen := map[string]bool{}
	tags := []string{}
	for _, tag := range raw {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	return tags
}

func uintValue(v any) uint64 {
	switch value := v.(type) {
	case uint64:
		return value
	case uint:
		return uint64(value)
	case int:
		return uint64(value)
	case int64:
		return uint64(value)
	case float64:
		return uint64(value)
	default:
		return 0
	}
}

func floatValue(v any) float64 {
	switch value := v.(type) {
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0
		}
		return value
	case float32:
		return float64(value)
	case uint64:
		return float64(value)
	case uint:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}

func int64Value(v any) int64 {
	switch value := v.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case uint64:
		if value > uint64(^uint64(0)>>1) {
			return int64(^uint64(0) >> 1)
		}
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func changeRatio(current, previous uint64) float64 {
	if previous == 0 {
		if current == 0 {
			return 0
		}
		return 999
	}
	return float64(int64(current)-int64(previous)) / float64(previous)
}

func bytesToMbps(bytes, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return bytes * 8 / seconds / 1000 / 1000
}

func ratio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}

func directionDistribution(rows []map[string]any) []model.TopItem {
	grouped := map[string]model.TopItem{}
	for _, row := range rows {
		key := directionLabel(stringValue(row["src"]), stringValue(row["dst"]))
		item := grouped[key]
		item.Key = key
		item.Bytes += uintValue(row["bytes"])
		item.Packets += uintValue(row["packets"])
		grouped[key] = item
	}
	items := make([]model.TopItem, 0, len(grouped))
	for _, item := range grouped {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Bytes > items[j].Bytes
	})
	return items
}

func directionLabel(src, dst string) string {
	srcInternal := isInternalIP(src)
	dstInternal := isInternalIP(dst)
	switch {
	case srcInternal && dstInternal:
		return "内网东西向"
	case srcInternal && !dstInternal:
		return "出站"
	case !srcInternal && dstInternal:
		return "入站"
	default:
		return "公网侧"
	}
}

type serviceInfo struct {
	Name     string
	Category string
	Risk     string
}

type exposureEndpoint struct {
	IP         string
	Port       string
	ClientIP   string
	Direction  string
	Confidence string
}

func inferExposureEndpoint(flow parsedFlow) (exposureEndpoint, bool) {
	srcInternal := isManagedAssetIP(flow.SrcIP)
	dstInternal := isManagedAssetIP(flow.DstIP)
	srcService := servicePortScore(flow.SrcPort)
	dstService := servicePortScore(flow.DstPort)

	switch {
	case !srcInternal && dstInternal:
		if dstService <= 0 {
			return exposureEndpoint{}, false
		}
		return exposureEndpoint{
			IP:         flow.DstIP,
			Port:       flow.DstPort,
			ClientIP:   flow.SrcIP,
			Direction:  "入站",
			Confidence: confidenceLabel(dstService),
		}, true
	case srcInternal && !dstInternal:
		if srcService <= 0 {
			return exposureEndpoint{}, false
		}
		return exposureEndpoint{
			IP:         flow.SrcIP,
			Port:       flow.SrcPort,
			ClientIP:   flow.DstIP,
			Direction:  "入站响应",
			Confidence: confidenceLabel(srcService),
		}, true
	case srcInternal && dstInternal:
		if dstService <= 0 && srcService <= 0 {
			return exposureEndpoint{}, false
		}
		if dstService >= srcService {
			return exposureEndpoint{
				IP:         flow.DstIP,
				Port:       flow.DstPort,
				ClientIP:   flow.SrcIP,
				Direction:  "内网服务",
				Confidence: confidenceLabel(dstService),
			}, true
		}
		return exposureEndpoint{
			IP:         flow.SrcIP,
			Port:       flow.SrcPort,
			ClientIP:   flow.DstIP,
			Direction:  "内网服务响应",
			Confidence: confidenceLabel(srcService),
		}, true
	default:
		return exposureEndpoint{}, false
	}
}

func servicePortScore(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 {
		return 0
	}
	if isKnownServicePort(port) {
		return 3
	}
	if n < 1024 {
		return 2
	}
	if n < 32768 {
		return 1
	}
	return 0
}

func confidenceLabel(score int) string {
	switch {
	case score >= 3:
		return "高"
	case score == 2:
		return "中"
	default:
		return "低"
	}
}

func identifyService(port, proto string) serviceInfo {
	if proto == "udp" && port == "53" {
		return serviceInfo{Name: "DNS", Category: "基础网络", Risk: "low"}
	}
	if service, ok := knownServices()[port]; ok {
		return service
	}
	if n, err := strconv.Atoi(port); err == nil && n >= 1024 {
		return serviceInfo{Name: "业务/动态端口", Category: "业务服务", Risk: "observe"}
	}
	return serviceInfo{Name: "未知服务", Category: "未知", Risk: "observe"}
}

func isKnownServicePort(port string) bool {
	_, ok := knownServices()[port]
	return ok
}

func portsForServiceSelector(dimension, key string) []string {
	ports := make([]string, 0)
	for port, service := range knownServices() {
		switch dimension {
		case "service":
			if strings.EqualFold(service.Name, key) {
				ports = append(ports, port)
			}
		case "service_category":
			if service.Category == key {
				ports = append(ports, port)
			}
		case "service_risk":
			if service.Risk == key {
				ports = append(ports, port)
			}
		}
	}
	sort.Strings(ports)
	return ports
}

func knownServices() map[string]serviceInfo {
	return map[string]serviceInfo{
		"20":    {Name: "FTP Data", Category: "文件传输", Risk: "medium"},
		"21":    {Name: "FTP", Category: "文件传输", Risk: "medium"},
		"22":    {Name: "SSH", Category: "远程管理", Risk: "high"},
		"23":    {Name: "Telnet", Category: "远程管理", Risk: "critical"},
		"25":    {Name: "SMTP", Category: "邮件", Risk: "medium"},
		"53":    {Name: "DNS", Category: "基础网络", Risk: "low"},
		"80":    {Name: "HTTP", Category: "Web", Risk: "low"},
		"110":   {Name: "POP3", Category: "邮件", Risk: "medium"},
		"123":   {Name: "NTP", Category: "基础网络", Risk: "low"},
		"139":   {Name: "NetBIOS", Category: "文件共享", Risk: "high"},
		"143":   {Name: "IMAP", Category: "邮件", Risk: "medium"},
		"389":   {Name: "LDAP", Category: "目录服务", Risk: "high"},
		"443":   {Name: "HTTPS", Category: "Web", Risk: "low"},
		"445":   {Name: "SMB", Category: "文件共享", Risk: "high"},
		"465":   {Name: "SMTPS", Category: "邮件", Risk: "medium"},
		"587":   {Name: "SMTP Submission", Category: "邮件", Risk: "medium"},
		"993":   {Name: "IMAPS", Category: "邮件", Risk: "medium"},
		"995":   {Name: "POP3S", Category: "邮件", Risk: "medium"},
		"1433":  {Name: "SQL Server", Category: "数据库", Risk: "critical"},
		"1521":  {Name: "Oracle", Category: "数据库", Risk: "critical"},
		"3306":  {Name: "MySQL", Category: "数据库", Risk: "critical"},
		"3389":  {Name: "RDP", Category: "远程管理", Risk: "critical"},
		"5432":  {Name: "PostgreSQL", Category: "数据库", Risk: "critical"},
		"5900":  {Name: "VNC", Category: "远程管理", Risk: "critical"},
		"6379":  {Name: "Redis", Category: "缓存", Risk: "critical"},
		"8080":  {Name: "HTTP Alternate", Category: "Web", Risk: "medium"},
		"8081":  {Name: "HTTP Alternate", Category: "Web", Risk: "medium"},
		"8443":  {Name: "HTTPS Alternate", Category: "Web", Risk: "medium"},
		"9200":  {Name: "Elasticsearch", Category: "搜索/数据", Risk: "critical"},
		"11211": {Name: "Memcached", Category: "缓存", Risk: "critical"},
		"27017": {Name: "MongoDB", Category: "数据库", Risk: "critical"},
	}
}

func riskWeight(risk string) int {
	switch risk {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func isInternalIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

func isManagedAssetIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback()
}

func averagePacketSize(bytes, packets uint64) uint64 {
	if packets == 0 {
		return 0
	}
	return bytes / packets
}

func assetRole(inbound, outbound uint64) string {
	total := inbound + outbound
	if total == 0 {
		return "空闲"
	}
	inboundShare := float64(inbound) / float64(total)
	outboundShare := float64(outbound) / float64(total)
	if inboundShare >= 0.7 {
		return "服务端"
	}
	if outboundShare >= 0.7 {
		return "外联源"
	}
	return "双向通信"
}

func insightWeight(severity string) int {
	switch severity {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func demoTopN(dimension string) []model.TopItem {
	if dimension == "dst_port" {
		return []model.TopItem{{Key: "443", Bytes: 88000000, Packets: 48000}, {Key: "80", Bytes: 22000000, Packets: 15000}, {Key: "53", Bytes: 6000000, Packets: 18000}}
	}
	if dimension == "protocol" {
		return []model.TopItem{{Key: "tcp", Bytes: 109000000, Packets: 72000}, {Key: "udp", Bytes: 15000000, Packets: 22000}}
	}
	if dimension == "flow" {
		return []model.TopItem{
			{Key: "10.10.1.42:53210 -> 172.20.2.10:443 / tcp", Bytes: 42000000, Packets: 14000},
			{Key: "10.10.1.77:53192 -> 172.20.2.81:80 / tcp", Bytes: 18000000, Packets: 7200},
			{Key: "10.10.1.18:49812 -> 172.20.2.144:53 / udp", Bytes: 5000000, Packets: 12000},
		}
	}
	if dimension == "pair" {
		return []model.TopItem{
			{Key: "10.10.1.42 -> 172.20.2.10", Bytes: 52000000, Packets: 18000},
			{Key: "10.10.1.77 -> 172.20.2.81", Bytes: 21000000, Packets: 8000},
			{Key: "10.10.1.18 -> 172.20.2.144", Bytes: 11000000, Packets: 6000},
		}
	}
	return []model.TopItem{{Key: "10.10.1.42", Bytes: 68000000, Packets: 21000}, {Key: "10.10.1.77", Bytes: 24000000, Packets: 9000}, {Key: "10.10.1.18", Bytes: 13000000, Packets: 7000}}
}

func demoAlerts() []model.AlertEvent {
	now := time.Now().Unix()
	return []model.AlertEvent{{
		ID:        "demo-top-flow",
		Severity:  "warning",
		Status:    "open",
		Subject:   "10.10.1.42:53210 -> 172.20.2.10:443 / tcp",
		Summary:   "单会话流量占比达到 42.0%",
		FirstSeen: now - 60,
		LastSeen:  now,
	}}
}

func demoSeries() []map[string]any {
	now := time.Now().Unix()
	rows := make([]map[string]any, 0, 12)
	for i := 11; i >= 0; i-- {
		rows = append(rows, map[string]any{
			"ts":      now - int64(i*60),
			"bytes":   40000000 + (11-i)*3200000,
			"packets": 24000 + (11-i)*900,
		})
	}
	return rows
}
