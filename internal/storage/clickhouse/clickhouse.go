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
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.flow_sessions_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    flow_key String,
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    protocol LowCardinality(String),
    service LowCardinality(String),
    category LowCardinality(String),
    risk LowCardinality(String),
    direction LowCardinality(String),
    server_ip String,
    server_port UInt16,
    client_ip String,
    confidence LowCardinality(String),
    bytes UInt64,
    packets UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, ts, dst_ip, dst_port, src_ip, protocol)
TTL ts + INTERVAL 7 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.capture_quality_5s
(
    ts DateTime,
    source_id LowCardinality(String),
    iface LowCardinality(String),
    rx_bytes UInt64,
    rx_packets UInt64,
    rx_dropped UInt64,
    rx_errors UInt64,
    tx_bytes UInt64,
    tx_packets UInt64,
    tx_dropped UInt64,
    tx_errors UInt64,
    packet_queue_len UInt64 DEFAULT 0,
    packet_queue_capacity UInt64 DEFAULT 0,
    window_queue_len UInt64 DEFAULT 0,
    window_queue_capacity UInt64 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (source_id, iface, ts)
TTL ts + INTERVAL 7 DAY`,
		`ALTER TABLE ` + s.database + `.capture_quality_5s ADD COLUMN IF NOT EXISTS packet_queue_len UInt64 DEFAULT 0`,
		`ALTER TABLE ` + s.database + `.capture_quality_5s ADD COLUMN IF NOT EXISTS packet_queue_capacity UInt64 DEFAULT 0`,
		`ALTER TABLE ` + s.database + `.capture_quality_5s ADD COLUMN IF NOT EXISTS window_queue_len UInt64 DEFAULT 0`,
		`ALTER TABLE ` + s.database + `.capture_quality_5s ADD COLUMN IF NOT EXISTS window_queue_capacity UInt64 DEFAULT 0`,
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
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.incident_notes
(
    id String,
    note String,
    author LowCardinality(String),
    created_at DateTime
)
ENGINE = MergeTree
PARTITION BY toDate(created_at)
ORDER BY (id, created_at)
TTL created_at + INTERVAL 365 DAY`,
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
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.operation_audit
(
    id String,
    ts DateTime,
    actor LowCardinality(String),
    action LowCardinality(String),
    target String,
    summary String,
    detail String,
    client_ip String
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, action, actor)
TTL ts + INTERVAL 365 DAY`,
		`CREATE TABLE IF NOT EXISTS ` + s.database + `.config_versions
(
    id String,
    ts DateTime,
    actor LowCardinality(String),
    scope LowCardinality(String),
    target String,
    action LowCardinality(String),
    summary String,
    config String,
    client_ip String
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (scope, target, ts)
TTL ts + INTERVAL 365 DAY`,
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
	if err := s.insertCaptureQuality(ctx, win.Capture); err != nil {
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
	if err := s.insertFlowSessions(ctx, win.SourceID, win.Iface, win.Ts, win.TopFlow); err != nil {
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

func (s *Store) DataQuality(ctx context.Context, minutes, limit int) (map[string]any, error) {
	if minutes <= 0 {
		minutes = 15
	}
	if limit <= 0 {
		limit = 20
	}
	sources, sourceErr := s.dataQualitySources(ctx, minutes, limit)
	gaps, gapErr := s.dataQualityGaps(ctx, minutes, max(limit*3, 60))
	now := time.Now().Unix()
	expectedPerSource := int64(minutes * 60 / 5)
	if expectedPerSource <= 0 {
		expectedPerSource = 1
	}
	totalWindows := int64(0)
	totalBytes := uint64(0)
	totalPackets := uint64(0)
	totalDrops := uint64(0)
	maxUtilization := 0.0
	staleSources := int64(0)
	latestWindow := int64(0)
	for _, row := range sources {
		windows := int64Value(row["windows"])
		totalWindows += windows
		totalBytes += uintValue(row["bytes"])
		totalPackets += uintValue(row["packets"])
		totalDrops += uintValue(row["drops"])
		if util := floatValue(row["max_utilization"]); util > maxUtilization {
			maxUtilization = util
		}
		if latest := int64Value(row["latest_window_ts"]); latest > latestWindow {
			latestWindow = latest
		}
		freshness := now - int64Value(row["latest_window_ts"])
		row["freshness_seconds"] = freshness
		row["coverage_ratio"] = ratioFloat(float64(windows), float64(expectedPerSource))
		row["status"] = dataQualitySourceStatus(freshness, floatValue(row["coverage_ratio"]), uintValue(row["drops"]))
		if stringValue(row["status"]) != "healthy" {
			staleSources++
		}
	}
	expectedTotal := expectedPerSource * int64(max(len(sources), 1))
	coverage := ratioFloat(float64(totalWindows), float64(expectedTotal))
	freshness := int64(0)
	if latestWindow > 0 {
		freshness = now - latestWindow
	}
	status := dataQualityStatus(freshness, coverage, len(gaps), staleSources)
	summary := map[string]any{
		"latest_window_ts":  latestWindow,
		"freshness_seconds": freshness,
		"expected_windows":  expectedTotal,
		"observed_windows":  totalWindows,
		"coverage_ratio":    coverage,
		"gap_count":         len(gaps),
		"stale_sources":     staleSources,
		"source_count":      len(sources),
		"interface_count":   countDistinctStrings(sources, "iface"),
		"bytes":             totalBytes,
		"packets":           totalPackets,
		"drops":             totalDrops,
		"max_utilization":   maxUtilization,
	}
	data := map[string]any{
		"generated_at":     now,
		"minutes":          minutes,
		"status":           status,
		"summary":          summary,
		"sources":          sources,
		"gaps":             gaps,
		"recommendations":  dataQualityRecommendations(status, summary, sources, gaps),
		"window_interval":  5,
		"degraded_reasons": []string{},
	}
	err := firstErr(sourceErr, gapErr)
	if len(sources) == 0 && err != nil {
		return demoDataQuality(minutes), err
	}
	return data, err
}

func (s *Store) CaptureQuality(ctx context.Context, minutes, limit int) (map[string]any, error) {
	if minutes <= 0 {
		minutes = 15
	}
	if limit <= 0 {
		limit = 20
	}
	q := fmt.Sprintf(`SELECT
    source_id,
    iface,
    count() AS windows,
    sum(rx_bytes) AS rx_bytes,
    sum(rx_packets) AS rx_packets,
    sum(rx_dropped) AS rx_dropped,
    sum(rx_errors) AS rx_errors,
    sum(tx_bytes) AS tx_bytes,
    sum(tx_packets) AS tx_packets,
    sum(tx_dropped) AS tx_dropped,
    sum(tx_errors) AS tx_errors,
    max(packet_queue_len) AS packet_queue_len,
    max(packet_queue_capacity) AS packet_queue_capacity,
    max(window_queue_len) AS window_queue_len,
    max(window_queue_capacity) AS window_queue_capacity,
    toUnixTimestamp(min(ts)) AS first_window_ts,
    toUnixTimestamp(max(ts)) AS latest_window_ts
FROM %s.capture_quality_5s
WHERE ts >= now() - INTERVAL %d MINUTE
GROUP BY source_id, iface
ORDER BY latest_window_ts DESC, rx_dropped DESC, rx_errors DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoCaptureQuality(minutes), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoCaptureQuality(minutes), err
	}
	now := time.Now().Unix()
	summary := map[string]any{
		"windows":          int64(0),
		"rx_bytes":         uint64(0),
		"rx_packets":       uint64(0),
		"rx_dropped":       uint64(0),
		"rx_errors":        uint64(0),
		"tx_bytes":         uint64(0),
		"tx_packets":       uint64(0),
		"tx_dropped":       uint64(0),
		"tx_errors":        uint64(0),
		"packet_queue_len": uint64(0),
		"window_queue_len": uint64(0),
		"queue_pressure":   float64(0),
		"source_count":     len(parsed.Data),
		"interface_count":  countDistinctStrings(parsed.Data, "iface"),
		"latest_window_ts": int64(0),
	}
	for _, row := range parsed.Data {
		summary["windows"] = int64Value(summary["windows"]) + int64Value(row["windows"])
		for _, key := range []string{"rx_bytes", "rx_packets", "rx_dropped", "rx_errors", "tx_bytes", "tx_packets", "tx_dropped", "tx_errors"} {
			summary[key] = uintValue(summary[key]) + uintValue(row[key])
		}
		if latest := int64Value(row["latest_window_ts"]); latest > int64Value(summary["latest_window_ts"]) {
			summary["latest_window_ts"] = latest
		}
		row["freshness_seconds"] = now - int64Value(row["latest_window_ts"])
		row["drop_ratio"] = ratioFloat(float64(uintValue(row["rx_dropped"])+uintValue(row["tx_dropped"])), float64(uintValue(row["rx_packets"])+uintValue(row["tx_packets"])))
		row["error_ratio"] = ratioFloat(float64(uintValue(row["rx_errors"])+uintValue(row["tx_errors"])), float64(uintValue(row["rx_packets"])+uintValue(row["tx_packets"])))
		row["packet_queue_pressure"] = ratioFloat(float64(uintValue(row["packet_queue_len"])), float64(uintValue(row["packet_queue_capacity"])))
		row["window_queue_pressure"] = ratioFloat(float64(uintValue(row["window_queue_len"])), float64(uintValue(row["window_queue_capacity"])))
		row["queue_pressure"] = maxFloat(floatValue(row["packet_queue_pressure"]), floatValue(row["window_queue_pressure"]))
		if uintValue(row["packet_queue_len"]) > uintValue(summary["packet_queue_len"]) {
			summary["packet_queue_len"] = uintValue(row["packet_queue_len"])
		}
		if uintValue(row["window_queue_len"]) > uintValue(summary["window_queue_len"]) {
			summary["window_queue_len"] = uintValue(row["window_queue_len"])
		}
		if floatValue(row["queue_pressure"]) > floatValue(summary["queue_pressure"]) {
			summary["queue_pressure"] = floatValue(row["queue_pressure"])
		}
		row["status"] = captureQualityRowStatus(row)
	}
	summary["drop_ratio"] = ratioFloat(float64(uintValue(summary["rx_dropped"])+uintValue(summary["tx_dropped"])), float64(uintValue(summary["rx_packets"])+uintValue(summary["tx_packets"])))
	summary["error_ratio"] = ratioFloat(float64(uintValue(summary["rx_errors"])+uintValue(summary["tx_errors"])), float64(uintValue(summary["rx_packets"])+uintValue(summary["tx_packets"])))
	status := captureQualityStatus(parsed.Data)
	return map[string]any{
		"generated_at":    now,
		"minutes":         minutes,
		"status":          status,
		"summary":         summary,
		"sources":         parsed.Data,
		"recommendations": captureQualityRecommendations(status, summary, parsed.Data),
	}, nil
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

func (s *Store) RecordAuditEvent(ctx context.Context, actor, action, target, summary string, detail map[string]any, clientIP string) error {
	actor = strings.TrimSpace(actor)
	action = strings.TrimSpace(action)
	target = strings.TrimSpace(target)
	summary = strings.TrimSpace(summary)
	clientIP = strings.TrimSpace(clientIP)
	if actor == "" {
		actor = "operator"
	}
	if action == "" {
		return fmt.Errorf("audit action is required")
	}
	if target == "" {
		target = "-"
	}
	if summary == "" {
		summary = action + " " + target
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	q := "INSERT INTO " + s.database + ".operation_audit FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"id":%q,"ts":%q,"actor":%q,"action":%q,"target":%q,"summary":%q,"detail":%q,"client_ip":%q}`+"\n",
		"audit-"+strconv.FormatInt(time.Now().UnixNano(), 36),
		formatTime(now),
		actor,
		action,
		target,
		summary,
		string(detailJSON),
		clientIP,
	))
}

func (s *Store) AuditEvents(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 80
	}
	q := fmt.Sprintf(`SELECT
    id,
    toUnixTimestamp(ts) AS ts,
    actor,
    action,
    target,
    summary,
    detail,
    client_ip
FROM %s.operation_audit
ORDER BY ts DESC
LIMIT %d
FORMAT JSON`, s.database, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoAuditEvents(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoAuditEvents(), err
	}
	for _, row := range parsed.Data {
		row["detail_text"] = stringValue(row["detail"])
	}
	return parsed.Data, nil
}

func (s *Store) RecordConfigVersion(ctx context.Context, actor, scope, target, action, summary string, config any, clientIP string) error {
	actor = strings.TrimSpace(actor)
	scope = strings.TrimSpace(scope)
	target = strings.TrimSpace(target)
	action = strings.TrimSpace(action)
	summary = strings.TrimSpace(summary)
	clientIP = strings.TrimSpace(clientIP)
	if actor == "" {
		actor = "operator"
	}
	if scope == "" {
		return fmt.Errorf("config scope is required")
	}
	if target == "" {
		target = "-"
	}
	if action == "" {
		action = "config.update"
	}
	if summary == "" {
		summary = action + " " + target
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	q := "INSERT INTO " + s.database + ".config_versions FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"id":%q,"ts":%q,"actor":%q,"scope":%q,"target":%q,"action":%q,"summary":%q,"config":%q,"client_ip":%q}`+"\n",
		"cfg-"+strconv.FormatInt(time.Now().UnixNano(), 36),
		formatTime(now),
		actor,
		scope,
		target,
		action,
		summary,
		string(configJSON),
		clientIP,
	))
}

func (s *Store) ConfigVersions(ctx context.Context, scope string, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 80
	}
	where := ""
	if strings.TrimSpace(scope) != "" {
		where = "WHERE scope = '" + escape(strings.TrimSpace(scope)) + "'"
	}
	q := fmt.Sprintf(`SELECT
    id,
    toUnixTimestamp(ts) AS ts,
    actor,
    scope,
    target,
    action,
    summary,
    config,
    client_ip
FROM %s.config_versions
%s
ORDER BY ts DESC
LIMIT %d
FORMAT JSON`, s.database, where, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return demoConfigVersions(), err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return demoConfigVersions(), err
	}
	for _, row := range parsed.Data {
		row["config_text"] = stringValue(row["config"])
	}
	return parsed.Data, nil
}

func (s *Store) ConfigVersion(ctx context.Context, id string) (map[string]any, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("config version id is required")
	}
	q := fmt.Sprintf(`SELECT
    id,
    toUnixTimestamp(ts) AS ts,
    actor,
    scope,
    target,
    action,
    summary,
    config,
    client_ip
FROM %s.config_versions
WHERE id = '%s'
ORDER BY ts DESC
LIMIT 1
FORMAT JSON`, s.database, escape(id))
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
	if len(parsed.Data) == 0 {
		return nil, fmt.Errorf("config version %q not found", id)
	}
	row := parsed.Data[0]
	row["config_text"] = stringValue(row["config"])
	return row, nil
}

func (s *Store) AlertStatusOverrides(ctx context.Context) (map[string]string, error) {
	q := fmt.Sprintf(`SELECT id, argMax(status, updated_at) AS status
FROM %s.alert_status_overrides
GROUP BY id
FORMAT JSON`, s.database)
	body, err := s.query(ctx, q)
	if err != nil {
		return map[string]string{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return map[string]string{}, err
	}
	result := map[string]string{}
	for _, row := range parsed.Data {
		result[stringValue(row["id"])] = stringValue(row["status"])
	}
	return result, nil
}

func (s *Store) AddIncidentNote(ctx context.Context, id, note, author string) (map[string]any, error) {
	id = strings.TrimSpace(id)
	note = strings.TrimSpace(note)
	author = strings.TrimSpace(author)
	if id == "" {
		return nil, fmt.Errorf("incident id is required")
	}
	if note == "" {
		return nil, fmt.Errorf("note is required")
	}
	if author == "" {
		author = "operator"
	}
	now := time.Now().Unix()
	q := "INSERT INTO " + s.database + ".incident_notes FORMAT JSONEachRow"
	if err := s.execBody(ctx, q, fmt.Sprintf(`{"id":%q,"note":%q,"author":%q,"created_at":%q}`+"\n", id, note, author, formatTime(now))); err != nil {
		return nil, err
	}
	return map[string]any{
		"id":         id,
		"type":       "note",
		"status":     "",
		"note":       note,
		"author":     author,
		"summary":    note,
		"created_at": now,
	}, nil
}

func (s *Store) IncidentTimeline(ctx context.Context, id string, limit int) ([]map[string]any, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return []map[string]any{}, fmt.Errorf("incident id is required")
	}
	if limit <= 0 {
		limit = 50
	}
	statusRows, statusErr := s.incidentStatusTimeline(ctx, id, limit)
	noteRows, noteErr := s.incidentNoteTimeline(ctx, id, limit)
	items := append(statusRows, noteRows...)
	sort.Slice(items, func(i, j int) bool {
		return int64Value(items[i]["created_at"]) > int64Value(items[j]["created_at"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, firstErr(statusErr, noteErr)
}

func (s *Store) incidentStatusTimeline(ctx context.Context, id string, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    id,
    'status' AS type,
    status,
    '' AS note,
    'operator' AS author,
    concat('状态变更为 ', status) AS summary,
    toUnixTimestamp(updated_at) AS created_at
FROM %s.alert_status_overrides
WHERE id = '%s'
ORDER BY updated_at DESC
LIMIT %d
FORMAT JSON`, s.database, escape(id), limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	return parsed.Data, nil
}

func (s *Store) incidentNoteTimeline(ctx context.Context, id string, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    id,
    'note' AS type,
    '' AS status,
    note,
    author,
    note AS summary,
    toUnixTimestamp(created_at) AS created_at
FROM %s.incident_notes
WHERE id = '%s'
ORDER BY created_at DESC
LIMIT %d
FORMAT JSON`, s.database, escape(id), limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	return parsed.Data, nil
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

func (s *Store) ServiceAnalytics(ctx context.Context, minutes, limit int) (map[string]any, error) {
	if limit <= 0 {
		limit = 12
	}
	services, serviceErr := s.TopN(ctx, "service", "src", limit, minutes)
	categories, categoryErr := s.TopN(ctx, "service_category", "src", limit, minutes)
	risks, riskErr := s.TopN(ctx, "service_risk", "src", limit, minutes)
	growth, growthErr := s.dimensionChanges(ctx, "service", "service", "src", minutes, limit)
	flows, flowErr := s.Sessions(ctx, "", minutes, limit*8)
	servicePorts, details := serviceAnalyticsFromSessions(flows, limit)
	summary := serviceAnalyticsSummary(services, categories, risks, details)
	data := map[string]any{
		"generated_at": time.Now().Unix(),
		"minutes":      minutes,
		"summary":      summary,
		"services":     services,
		"categories":   categories,
		"risks":        risks,
		"growth":       capacityGrowthRows(growth, limit),
		"ports":        servicePorts,
		"details":      details,
	}
	err := firstErr(serviceErr, categoryErr, riskErr, growthErr, flowErr)
	if err != nil && len(services) == 0 && len(details) == 0 {
		return demoServiceAnalytics(minutes), err
	}
	return data, err
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
	rows, err := s.flowSessions(ctx, q, minutes, limit)
	if err == nil && len(rows) > 0 {
		return rows, nil
	}
	fallbackRows, fallbackErr := s.legacySessions(ctx, q, minutes, limit)
	if fallbackErr != nil {
		return fallbackRows, firstErr(err, fallbackErr)
	}
	return fallbackRows, err
}

func (s *Store) flowSessions(ctx context.Context, q string, minutes, limit int) ([]map[string]any, error) {
	where := ""
	if q = strings.TrimSpace(q); q != "" {
		escaped := escape(q)
		where = fmt.Sprintf(` AND (
    position(flow_key, '%s') > 0 OR
    position(src_ip, '%s') > 0 OR
    position(dst_ip, '%s') > 0 OR
    position(service, '%s') > 0 OR
    position(category, '%s') > 0 OR
    position(protocol, '%s') > 0 OR
    toString(src_port) = '%s' OR
    toString(dst_port) = '%s'
)`, escaped, escaped, escaped, escaped, escaped, escaped, escaped, escaped)
	}
	query := fmt.Sprintf(`SELECT
    flow_key AS key,
    any(src_ip) AS src_ip,
    any(toString(src_port)) AS src_port,
    any(dst_ip) AS dst_ip,
    any(toString(dst_port)) AS dst_port,
    any(protocol) AS protocol,
    any(service) AS service,
    any(category) AS category,
    any(risk) AS risk,
    any(direction) AS direction,
    any(server_ip) AS server_ip,
    any(toString(server_port)) AS server_port,
    any(client_ip) AS client_ip,
    any(confidence) AS confidence,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    min(toUnixTimestamp(ts)) AS first_seen,
    max(toUnixTimestamp(ts)) AS last_seen
FROM %s.flow_sessions_5s
WHERE ts >= now() - INTERVAL %d MINUTE%s
GROUP BY key
ORDER BY bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, where, limit)
	body, err := s.query(ctx, query)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	for _, row := range parsed.Data {
		row["avg_packet_size"] = ratio(floatValue(row["bytes"]), floatValue(row["packets"]))
	}
	return parsed.Data, nil
}

func (s *Store) legacySessions(ctx context.Context, q string, minutes, limit int) ([]map[string]any, error) {
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

func (s *Store) CapacityPlanning(ctx context.Context, minutes, limit int, bandwidthMbps uint64) (map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}
	if bandwidthMbps == 0 {
		bandwidthMbps = 1000
	}
	baseline, baselineErr := s.trafficBaseline(ctx, minutes)
	previous, previousErr := s.trafficBaselineWindow(ctx, minutes, minutes*2)
	trend, trendErr := s.capacityMinuteTrend(ctx, minutes)
	srcGrowth, srcErr := s.dimensionChanges(ctx, "src_ip", "ip", "src", minutes, limit)
	portGrowth, portErr := s.dimensionChanges(ctx, "dst_port", "dst_port", "src", minutes, limit)
	serviceGrowth, serviceErr := s.dimensionChanges(ctx, "service", "service", "src", minutes, limit)

	peakMbps := floatValue(baseline["peak_mbps"])
	p95Mbps := floatValue(baseline["p95_mbps"])
	avgMbps := floatValue(baseline["avg_mbps"])
	prevPeakMbps := floatValue(previous["peak_mbps"])
	growthMbps := peakMbps - prevPeakMbps
	headroomMbps := float64(bandwidthMbps) - peakMbps
	if headroomMbps < 0 {
		headroomMbps = 0
	}
	headroomRatio := ratio(headroomMbps, float64(bandwidthMbps))
	etaMinutes := float64(0)
	if growthMbps > 0 {
		etaMinutes = headroomMbps / growthMbps * float64(minutes)
	}
	summary := map[string]any{
		"minutes":             minutes,
		"bandwidth_mbps":      bandwidthMbps,
		"avg_mbps":            avgMbps,
		"peak_mbps":           peakMbps,
		"p95_mbps":            p95Mbps,
		"previous_peak_mbps":  prevPeakMbps,
		"growth_mbps":         growthMbps,
		"growth_ratio":        ratio(growthMbps, prevPeakMbps),
		"headroom_mbps":       headroomMbps,
		"headroom_ratio":      headroomRatio,
		"peak_utilization":    ratio(peakMbps, float64(bandwidthMbps)),
		"p95_utilization":     ratio(p95Mbps, float64(bandwidthMbps)),
		"saturation_eta_mins": etaMinutes,
		"risk_level":          capacityRiskLevel(headroomRatio, growthMbps, etaMinutes),
	}
	data := map[string]any{
		"generated_at":       time.Now().Unix(),
		"minutes":            minutes,
		"summary":            summary,
		"trend":              trend,
		"top_src_growth":     capacityGrowthRows(srcGrowth, limit),
		"top_port_growth":    capacityGrowthRows(portGrowth, limit),
		"top_service_growth": capacityGrowthRows(serviceGrowth, limit),
		"recommendations":    capacityRecommendations(summary, srcGrowth, portGrowth, serviceGrowth),
	}
	err := firstErr(baselineErr, previousErr, trendErr, srcErr, portErr, serviceErr)
	if err != nil && len(trend) == 0 {
		return demoCapacityPlanning(minutes, bandwidthMbps), err
	}
	return data, err
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

func (s *Store) TrafficAnomalies(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	linkRows, linkErr := s.linkAnomalies(ctx, minutes)
	srcChanges, srcErr := s.dimensionChanges(ctx, "src_ip", "ip", "src", minutes, limit)
	dstChanges, dstErr := s.dimensionChanges(ctx, "dst_ip", "ip", "dst", minutes, limit)
	portChanges, portErr := s.dimensionChanges(ctx, "dst_port", "dst_port", "src", minutes, limit)
	protoChanges, protoErr := s.dimensionChanges(ctx, "protocol", "protocol", "src", minutes, limit)
	serviceChanges, serviceErr := s.dimensionChanges(ctx, "service", "service", "src", minutes, limit)

	items := make([]map[string]any, 0, len(linkRows)+len(srcChanges)+len(dstChanges)+len(portChanges)+len(protoChanges)+len(serviceChanges))
	items = append(items, linkRows...)
	for _, rows := range [][]map[string]any{srcChanges, dstChanges, portChanges, protoChanges, serviceChanges} {
		for _, row := range rows {
			if anomaly, ok := anomalyFromChange(row, minutes); ok {
				items = append(items, anomaly)
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if insightWeight(stringValue(items[i]["severity"])) != insightWeight(stringValue(items[j]["severity"])) {
			return insightWeight(stringValue(items[i]["severity"])) > insightWeight(stringValue(items[j]["severity"]))
		}
		if int64Value(items[i]["score"]) != int64Value(items[j]["score"]) {
			return int64Value(items[i]["score"]) > int64Value(items[j]["score"])
		}
		return int64Value(items[i]["delta_bytes"]) > int64Value(items[j]["delta_bytes"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	err := firstErr(linkErr, srcErr, dstErr, portErr, protoErr, serviceErr)
	if len(items) == 0 && err != nil {
		return demoTrafficAnomalies(), err
	}
	return items, err
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

func (s *Store) AssetRiskPosture(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	assets, assetErr := s.Assets(ctx, minutes, max(limit, 100))
	exposures, exposureErr := s.ServiceExposure(ctx, minutes, max(limit*3, 120))
	externalRows, externalErr := s.ExternalAccess(ctx, minutes, max(limit*3, 160))
	incidents, incidentErr := s.SecurityIncidents(ctx, minutes, max(limit*3, 120))
	anomalies, anomalyErr := s.TrafficAnomalies(ctx, minutes, max(limit*3, 120))

	rows := map[string]map[string]any{}
	for _, asset := range assets {
		ip := stringValue(asset["ip"])
		if ip == "" {
			continue
		}
		row := ensureAssetRiskRow(rows, ip)
		row["name"] = stringValue(asset["name"])
		row["owner"] = stringValue(asset["owner"])
		row["business"] = stringValue(asset["business"])
		row["environment"] = stringValue(asset["environment"])
		row["criticality"] = stringValue(asset["criticality"])
		row["role"] = stringValue(asset["role"])
		row["total_bytes"] = uintValue(asset["total_bytes"])
		row["total_packets"] = uintValue(asset["total_packets"])
		row["last_seen"] = int64Value(asset["last_seen"])
		addAssetRiskScore(row, criticalityRiskScore(stringValue(asset["criticality"])), "资产重要性："+assetCriticalityLabel(stringValue(asset["criticality"])))
	}
	for _, exposure := range exposures {
		ip := stringValue(exposure["ip"])
		if ip == "" {
			continue
		}
		row := ensureAssetRiskRow(rows, ip)
		row["exposed_services"] = int64Value(row["exposed_services"]) + 1
		if riskWeight(stringValue(exposure["risk"])) >= riskWeight("high") {
			row["high_risk_services"] = int64Value(row["high_risk_services"]) + 1
		}
		row["external_bytes"] = uintValue(row["external_bytes"]) + uintValue(exposure["bytes"])
		addAssetRiskScore(row, serviceExposureRiskScore(stringValue(exposure["risk"])), "服务暴露："+stringValue(exposure["service"])+" / "+stringValue(exposure["port"]))
	}
	publicPeers := map[string]map[string]bool{}
	for _, access := range externalRows {
		ip := stringValue(access["internal_ip"])
		if ip == "" {
			continue
		}
		row := ensureAssetRiskRow(rows, ip)
		row["external_sessions"] = int64Value(row["external_sessions"]) + int64Value(access["session_count"])
		row["external_bytes"] = uintValue(row["external_bytes"]) + uintValue(access["bytes"])
		if publicPeers[ip] == nil {
			publicPeers[ip] = map[string]bool{}
		}
		publicPeers[ip][stringValue(access["public_ip"])] = true
		addAssetRiskScore(row, externalAccessRiskScore(stringValue(access["risk"]), stringValue(access["direction"])), "公网访问："+stringValue(access["direction"])+" / "+stringValue(access["service"]))
	}
	for ip, peers := range publicPeers {
		rows[ip]["external_peers"] = int64(len(peers))
	}
	for _, incident := range incidents {
		ip := firstIPInText(stringValue(incident["subject"]))
		if ip == "" {
			continue
		}
		row := ensureAssetRiskRow(rows, ip)
		row["open_incidents"] = int64Value(row["open_incidents"]) + 1
		if stringValue(incident["severity"]) == "critical" {
			row["critical_incidents"] = int64Value(row["critical_incidents"]) + 1
		}
		addAssetRiskScore(row, incidentRiskScore(stringValue(incident["severity"]), int64Value(incident["score"])), "事件："+stringValue(incident["summary"]))
	}
	for _, anomaly := range anomalies {
		dimension := stringValue(anomaly["dimension"])
		if dimension != "src_ip" && dimension != "dst_ip" {
			continue
		}
		ip := stringValue(anomaly["key"])
		if ip == "" {
			continue
		}
		row := ensureAssetRiskRow(rows, ip)
		row["anomaly_count"] = int64Value(row["anomaly_count"]) + 1
		addAssetRiskScore(row, anomalyRiskScore(stringValue(anomaly["severity"]), int64Value(anomaly["score"])), "异常："+stringValue(anomaly["summary"]))
	}
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		score := min(int64Value(row["risk_score"]), int64(100))
		row["risk_score"] = score
		row["risk_level"] = assetRiskLevel(score)
		row["recommended_action"] = assetRiskAction(row)
		if stringValue(row["top_finding"]) == "" {
			row["top_finding"] = "近期活跃资产，暂无显著风险信号"
		}
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		if int64Value(result[i]["risk_score"]) != int64Value(result[j]["risk_score"]) {
			return int64Value(result[i]["risk_score"]) > int64Value(result[j]["risk_score"])
		}
		return uintValue(result[i]["total_bytes"]) > uintValue(result[j]["total_bytes"])
	})
	if len(result) > limit {
		result = result[:limit]
	}
	err := firstErr(assetErr, exposureErr, externalErr, incidentErr, anomalyErr)
	if len(result) == 0 && err != nil {
		return demoAssetRiskPosture(), err
	}
	return result, err
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
	scans, scanErr := s.scanInsights(ctx, minutes, limit)

	items := make([]map[string]any, 0, len(flows)+len(fanouts)+len(ports)+len(serviceRisks)+len(qosMarks)+len(scans))
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
	items = append(items, scans...)
	sort.Slice(items, func(i, j int) bool {
		if insightWeight(stringValue(items[i]["severity"])) != insightWeight(stringValue(items[j]["severity"])) {
			return insightWeight(stringValue(items[i]["severity"])) > insightWeight(stringValue(items[j]["severity"]))
		}
		return uintValue(items[i]["bytes"]) > uintValue(items[j]["bytes"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	if len(items) == 0 && (totalErr != nil || flowErr != nil || fanoutErr != nil || portErr != nil || serviceRiskErr != nil || qosErr != nil || scanErr != nil) {
		return demoSecurityInsights(), firstErr(totalErr, flowErr, fanoutErr, portErr, serviceRiskErr, qosErr, scanErr)
	}
	return items, firstErr(totalErr, flowErr, fanoutErr, portErr, serviceRiskErr, qosErr, scanErr)
}

func (s *Store) DetectionRuleFindings(ctx context.Context, rules []model.DetectionRule, minutes, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	items := []map[string]any{}
	var err error
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		rows, ruleErr := s.detectionRuleRows(ctx, rule, minutes, limit)
		err = firstErr(err, ruleErr)
		items = append(items, rows...)
	}
	sort.Slice(items, func(i, j int) bool {
		if insightWeight(stringValue(items[i]["severity"])) != insightWeight(stringValue(items[j]["severity"])) {
			return insightWeight(stringValue(items[i]["severity"])) > insightWeight(stringValue(items[j]["severity"]))
		}
		if int64Value(items[i]["score"]) != int64Value(items[j]["score"]) {
			return int64Value(items[i]["score"]) > int64Value(items[j]["score"])
		}
		return floatValue(items[i]["value"]) > floatValue(items[j]["value"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, err
}

func (s *Store) SecurityIncidents(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	alerts, alertErr := s.Alerts(ctx, max(limit, 50), minutes)
	insights, insightErr := s.SecurityInsights(ctx, minutes, max(limit, 50))
	anomalies, anomalyErr := s.TrafficAnomalies(ctx, minutes, max(limit, 50))
	overrides, overrideErr := s.AlertStatusOverrides(ctx)
	now := time.Now().Unix()
	items := make([]map[string]any, 0, len(alerts)+len(insights)+len(anomalies))
	for _, alert := range alerts {
		items = append(items, incidentFromAlert(alert))
	}
	for _, insight := range insights {
		items = append(items, incidentFromInsight(insight, now, minutes))
	}
	for _, anomaly := range anomalies {
		items = append(items, incidentFromAnomaly(anomaly, now, minutes))
	}
	applyIncidentStatusOverrides(items, overrides)
	sort.Slice(items, func(i, j int) bool {
		if incidentStatusWeight(stringValue(items[i]["status"])) != incidentStatusWeight(stringValue(items[j]["status"])) {
			return incidentStatusWeight(stringValue(items[i]["status"])) > incidentStatusWeight(stringValue(items[j]["status"]))
		}
		if insightWeight(stringValue(items[i]["severity"])) != insightWeight(stringValue(items[j]["severity"])) {
			return insightWeight(stringValue(items[i]["severity"])) > insightWeight(stringValue(items[j]["severity"]))
		}
		if int64Value(items[i]["score"]) != int64Value(items[j]["score"]) {
			return int64Value(items[i]["score"]) > int64Value(items[j]["score"])
		}
		return int64Value(items[i]["last_seen"]) > int64Value(items[j]["last_seen"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	if len(items) == 0 && (alertErr != nil || insightErr != nil || anomalyErr != nil || overrideErr != nil) {
		return demoSecurityIncidents(now), firstErr(alertErr, insightErr, anomalyErr, overrideErr)
	}
	return items, firstErr(alertErr, insightErr, anomalyErr, overrideErr)
}

func (s *Store) SecurityIncidentContext(ctx context.Context, subject, kind string, minutes, limit int) (map[string]any, error) {
	selector := incidentContextSelector(subject, kind)
	relationDimension := selector["dimension"]
	relationKey := selector["key"]
	if relationDimension == "link" {
		relationDimension = "flow"
		relationKey = ""
	}
	relations, relationErr := s.ObjectRelations(ctx, relationDimension, relationKey, selector["direction"], minutes, limit)
	sessions, sessionErr := s.Sessions(ctx, selector["query"], minutes, limit)
	searchRows, searchErr := s.Search(ctx, selector["query"], minutes, limit)
	insights, insightErr := s.incidentRelatedInsights(ctx, selector["dimension"], selector["key"], selector["query"], minutes, limit)
	anomalies, anomalyErr := s.incidentRelatedAnomalies(ctx, selector["dimension"], selector["key"], selector["query"], minutes, limit)
	context := map[string]any{
		"subject":          subject,
		"kind":             kind,
		"minutes":          minutes,
		"selector":         selector,
		"relations":        relations,
		"sessions":         sessions,
		"search_results":   searchRows,
		"insights":         insights,
		"anomalies":        anomalies,
		"playbook_actions": incidentPlaybookActions(kind, selector["dimension"]),
	}
	if selector["dimension"] == "ip" && selector["key"] != "" {
		profile, profileErr := s.IPProfile(ctx, selector["key"], minutes)
		context["ip_profile"] = profile
		return context, firstErr(relationErr, sessionErr, searchErr, insightErr, anomalyErr, profileErr)
	}
	if selector["dimension"] == "dst_port" && selector["key"] != "" {
		profile, profileErr := s.PortProfile(ctx, selector["key"], minutes)
		context["port_profile"] = profile
		return context, firstErr(relationErr, sessionErr, searchErr, insightErr, anomalyErr, profileErr)
	}
	return context, firstErr(relationErr, sessionErr, searchErr, insightErr, anomalyErr)
}

func (s *Store) ReportOverview(ctx context.Context, minutes, limit int) (map[string]any, error) {
	if limit <= 0 {
		limit = 10
	}
	summary, summaryErr := s.Summary(ctx, minutes)
	analysis, analysisErr := s.TrafficAnalysis(ctx, minutes)
	assetRisks, assetErr := s.AssetRiskPosture(ctx, minutes, limit)
	incidents, incidentErr := s.SecurityIncidents(ctx, minutes, limit)
	anomalies, anomalyErr := s.TrafficAnomalies(ctx, minutes, limit)
	exposures, exposureErr := s.ServiceExposure(ctx, minutes, limit)
	externalRows, externalErr := s.ExternalAccess(ctx, minutes, limit)
	topSrc, srcErr := s.TopN(ctx, "ip", "src", limit, minutes)
	topPorts, portErr := s.TopN(ctx, "dst_port", "src", limit, minutes)
	topServices, serviceErr := s.TopN(ctx, "service", "src", limit, minutes)

	metrics := map[string]any{
		"minutes":              minutes,
		"bytes":                uintValue(summary["bytes"]),
		"packets":              uintValue(summary["packets"]),
		"utilization":          floatValue(summary["utilization"]),
		"asset_count":          len(assetRisks),
		"critical_assets":      countMapsByString(assetRisks, "risk_level", "critical"),
		"open_incidents":       countMapsByString(incidents, "status", "open"),
		"critical_incidents":   countMapsByString(incidents, "severity", "critical"),
		"anomaly_count":        len(anomalies),
		"critical_anomalies":   countMapsByString(anomalies, "severity", "critical"),
		"exposed_services":     len(exposures),
		"high_risk_services":   countHighRiskRows(exposures),
		"external_access":      len(externalRows),
		"external_session_sum": sumIntMaps(externalRows, "session_count"),
		"avg_mbps":             floatValue(mapValue(analysis, "baseline", "avg_mbps")),
		"peak_mbps":            floatValue(mapValue(analysis, "baseline", "peak_mbps")),
		"p95_mbps":             floatValue(mapValue(analysis, "baseline", "p95_mbps")),
	}
	report := map[string]any{
		"generated_at":    time.Now().Unix(),
		"minutes":         minutes,
		"summary":         metrics,
		"asset_risks":     assetRisks,
		"incidents":       incidents,
		"anomalies":       anomalies,
		"exposures":       exposures,
		"external_access": externalRows,
		"top_src":         topSrc,
		"top_ports":       topPorts,
		"top_services":    topServices,
		"recommendations": reportRecommendations(metrics, assetRisks, incidents, anomalies, exposures),
	}
	err := firstErr(summaryErr, analysisErr, assetErr, incidentErr, anomalyErr, exposureErr, externalErr, srcErr, portErr, serviceErr)
	if err != nil && len(assetRisks) == 0 && len(incidents) == 0 {
		return demoReportOverview(minutes), err
	}
	return report, err
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

func (s *Store) linkAnomalies(ctx context.Context, minutes int) ([]map[string]any, error) {
	current, currentErr := s.linkWindowTotal(ctx, 0, minutes)
	previous, previousErr := s.linkWindowTotal(ctx, minutes, minutes*2)
	deltaBytes := int64(current.Bytes) - int64(previous.Bytes)
	ratioValue := changeRatio(current.Bytes, previous.Bytes)
	if deltaBytes <= 0 || (current.Bytes < 5*1024*1024 && ratioValue < 1.5) {
		return []map[string]any{}, firstErr(currentErr, previousErr)
	}
	severity := "warning"
	score := 65
	if ratioValue >= 2 || current.Bytes >= previous.Bytes+100*1024*1024 {
		severity = "critical"
		score = 88
	}
	return []map[string]any{{
		"kind":             "link_burst",
		"dimension":        "link",
		"key":              "链路总流量",
		"severity":         severity,
		"summary":          fmt.Sprintf("近 %d 分钟链路总流量较上一周期增长 %s", minutes, formatChangeRatioText(ratioValue)),
		"current_bytes":    current.Bytes,
		"baseline_bytes":   previous.Bytes,
		"delta_bytes":      deltaBytes,
		"current_packets":  current.Packets,
		"baseline_packets": previous.Packets,
		"delta_packets":    int64(current.Packets) - int64(previous.Packets),
		"change_ratio":     ratioValue,
		"score":            score,
	}}, firstErr(currentErr, previousErr)
}

func (s *Store) linkWindowTotal(ctx context.Context, startMinutesAgo, endMinutesAgo int) (model.TopItem, error) {
	q := fmt.Sprintf(`SELECT 'link' AS key, ifNull(sum(bytes), 0) AS bytes, ifNull(sum(packets), 0) AS packets
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
    AND ts < now() - INTERVAL %d MINUTE
FORMAT JSON`, s.database, endMinutesAgo, startMinutesAgo)
	body, err := s.query(ctx, q)
	if err != nil {
		return model.TopItem{Key: "link"}, err
	}
	var parsed struct {
		Data []model.TopItem `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return model.TopItem{Key: "link"}, err
	}
	if len(parsed.Data) == 0 {
		return model.TopItem{Key: "link"}, nil
	}
	return parsed.Data[0], nil
}

func (s *Store) trafficBaseline(ctx context.Context, minutes int) (map[string]any, error) {
	return s.trafficBaselineWindow(ctx, 0, minutes)
}

func (s *Store) trafficBaselineWindow(ctx context.Context, startMinutesAgo, endMinutesAgo int) (map[string]any, error) {
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
    AND ts < now() - INTERVAL %d MINUTE
FORMAT JSON`, s.database, endMinutesAgo, startMinutesAgo)
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

func (s *Store) capacityMinuteTrend(ctx context.Context, minutes int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    toUnixTimestamp(toStartOfMinute(ts)) AS ts,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    max(utilization) AS utilization
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
GROUP BY ts
ORDER BY ts ASC
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	for _, row := range parsed.Data {
		row["mbps"] = bytesToMbps(floatValue(row["bytes"]), 60)
	}
	return parsed.Data, nil
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

func (s *Store) scanInsights(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	sessions, err := s.Sessions(ctx, "", minutes, max(limit*10, 80))
	if err != nil {
		return nil, err
	}
	type scanBucket struct {
		subject  string
		ports    map[string]bool
		targets  map[string]bool
		bytes    uint64
		packets  uint64
		sessions uint64
	}
	inbound := map[string]*scanBucket{}
	outbound := map[string]*scanBucket{}
	for _, session := range sessions {
		access, ok := externalAccessRow(session)
		if !ok {
			continue
		}
		publicIP := stringValue(access["public_ip"])
		internalIP := stringValue(access["internal_ip"])
		port := stringValue(access["port"])
		direction := stringValue(access["direction"])
		if publicIP == "" || internalIP == "" || port == "" {
			continue
		}
		if strings.Contains(direction, "入站") {
			key := publicIP + " -> " + internalIP
			bucket := inbound[key]
			if bucket == nil {
				bucket = &scanBucket{subject: key, ports: map[string]bool{}, targets: map[string]bool{}}
				inbound[key] = bucket
			}
			bucket.ports[port] = true
			bucket.targets[internalIP] = true
			bucket.bytes += uintValue(session["bytes"])
			bucket.packets += uintValue(session["packets"])
			bucket.sessions++
			continue
		}
		if strings.Contains(direction, "出站") {
			bucket := outbound[internalIP]
			if bucket == nil {
				bucket = &scanBucket{subject: internalIP, ports: map[string]bool{}, targets: map[string]bool{}}
				outbound[internalIP] = bucket
			}
			bucket.ports[port] = true
			bucket.targets[publicIP] = true
			bucket.bytes += uintValue(session["bytes"])
			bucket.packets += uintValue(session["packets"])
			bucket.sessions++
		}
	}
	items := make([]map[string]any, 0)
	for _, bucket := range inbound {
		portCount := len(bucket.ports)
		if portCount < 3 && bucket.sessions < 30 {
			continue
		}
		severity := "warning"
		score := 65 + portCount*5
		kind := "external_port_scan"
		summary := fmt.Sprintf("公网对端在 %d 分钟内访问内部资产 %d 个端口、%d 条会话", minutes, portCount, bucket.sessions)
		if portCount < 3 {
			kind = "external_session_burst"
			score = 68 + int(bucket.sessions/10)
			summary = fmt.Sprintf("公网对端在 %d 分钟内对内部资产单端口建立 %d 条会话", minutes, bucket.sessions)
		}
		if portCount >= 10 || bucket.sessions >= 80 {
			severity = "critical"
			score = 90
		}
		items = append(items, map[string]any{
			"kind":     kind,
			"severity": severity,
			"subject":  bucket.subject,
			"summary":  summary,
			"bytes":    bucket.bytes,
			"packets":  bucket.packets,
			"score":    min(score, 100),
		})
	}
	for _, bucket := range outbound {
		targetCount := len(bucket.targets)
		portCount := len(bucket.ports)
		if targetCount < 5 && portCount < 5 && bucket.sessions < 20 {
			continue
		}
		severity := "warning"
		score := 55 + targetCount*3 + portCount*2
		if targetCount >= 20 || portCount >= 12 || bucket.sessions >= 60 {
			severity = "critical"
			score = 88
		}
		items = append(items, map[string]any{
			"kind":     "outbound_probe",
			"severity": severity,
			"subject":  bucket.subject,
			"summary":  fmt.Sprintf("内部主机在 %d 分钟内访问 %d 个公网目标、%d 个端口、%d 条会话", minutes, targetCount, portCount, bucket.sessions),
			"bytes":    bucket.bytes,
			"packets":  bucket.packets,
			"score":    min(score, 100),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if int64Value(items[i]["score"]) != int64Value(items[j]["score"]) {
			return int64Value(items[i]["score"]) > int64Value(items[j]["score"])
		}
		return uintValue(items[i]["bytes"]) > uintValue(items[j]["bytes"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
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

func (s *Store) insertCaptureQuality(ctx context.Context, row *model.CaptureQualityWindow) error {
	if row == nil {
		return nil
	}
	q := "INSERT INTO " + s.database + ".capture_quality_5s FORMAT JSONEachRow"
	return s.execBody(ctx, q, fmt.Sprintf(`{"ts":%q,"source_id":%q,"iface":%q,"rx_bytes":%d,"rx_packets":%d,"rx_dropped":%d,"rx_errors":%d,"tx_bytes":%d,"tx_packets":%d,"tx_dropped":%d,"tx_errors":%d,"packet_queue_len":%d,"packet_queue_capacity":%d,"window_queue_len":%d,"window_queue_capacity":%d}`+"\n",
		formatTime(row.Ts),
		row.SourceID,
		row.Iface,
		row.RxBytes,
		row.RxPackets,
		row.RxDropped,
		row.RxErrors,
		row.TxBytes,
		row.TxPackets,
		row.TxDropped,
		row.TxErrors,
		row.PacketQueueLen,
		row.PacketQueueCapacity,
		row.WindowQueueLen,
		row.WindowQueueCapacity,
	))
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

func (s *Store) insertFlowSessions(ctx context.Context, sourceID, iface string, ts int64, rows []model.TopItem) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	for _, row := range rows {
		parsed, ok := parseFlowKey(row.Key)
		if !ok {
			continue
		}
		service := identifyService(parsed.DstPort, parsed.Proto)
		session := sessionRow(row, ts, ts)
		fmt.Fprintf(&b, `{"ts":%q,"source_id":%q,"iface":%q,"flow_key":%q,"src_ip":%q,"src_port":%d,"dst_ip":%q,"dst_port":%d,"protocol":%q,"service":%q,"category":%q,"risk":%q,"direction":%q,"server_ip":%q,"server_port":%d,"client_ip":%q,"confidence":%q,"bytes":%d,"packets":%d}`+"\n",
			formatTime(ts),
			sourceID,
			iface,
			row.Key,
			parsed.SrcIP,
			uint16Value(parsed.SrcPort),
			parsed.DstIP,
			uint16Value(parsed.DstPort),
			parsed.Proto,
			service.Name,
			service.Category,
			service.Risk,
			stringValue(session["direction"]),
			stringValue(session["server_ip"]),
			uint16Value(stringValue(session["server_port"])),
			stringValue(session["client_ip"]),
			stringValue(session["confidence"]),
			row.Bytes,
			row.Packets,
		)
	}
	if b.Len() == 0 {
		return nil
	}
	return s.execBody(ctx, "INSERT INTO "+s.database+".flow_sessions_5s FORMAT JSONEachRow", b.String())
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

func demoDataQuality(minutes int) map[string]any {
	now := time.Now().Unix()
	sources := []map[string]any{
		{
			"source_id":         "dev-source-01",
			"iface":             "mock0",
			"windows":           int64(170),
			"bytes":             uint64(158000000),
			"packets":           uint64(98000),
			"drops":             uint64(0),
			"max_utilization":   0.08,
			"first_window_ts":   now - int64(minutes*60),
			"latest_window_ts":  now - 5,
			"freshness_seconds": int64(5),
			"coverage_ratio":    0.94,
			"status":            "healthy",
		},
	}
	gaps := []map[string]any{
		{"source_id": "dev-source-01", "iface": "mock0", "start_ts": now - 480, "end_ts": now - 455, "duration_seconds": int64(25), "missing_windows": 4},
	}
	return map[string]any{
		"generated_at":    now,
		"minutes":         minutes,
		"status":          "warning",
		"window_interval": 5,
		"summary": map[string]any{
			"latest_window_ts":  now - 5,
			"freshness_seconds": int64(5),
			"expected_windows":  int64(minutes * 60 / 5),
			"observed_windows":  int64(170),
			"coverage_ratio":    0.94,
			"gap_count":         len(gaps),
			"stale_sources":     int64(0),
			"source_count":      len(sources),
			"interface_count":   1,
			"bytes":             uint64(158000000),
			"packets":           uint64(98000),
			"drops":             uint64(0),
			"max_utilization":   0.08,
		},
		"sources": sources,
		"gaps":    gaps,
		"recommendations": []map[string]string{
			{"level": "warning", "title": "定位采集断档", "detail": "示例采集源存在短时断档，真实数据接入后会自动展示实际断档"},
		},
		"degraded_reasons": []string{"demo data"},
	}
}

func demoCaptureQuality(minutes int) map[string]any {
	now := time.Now().Unix()
	sources := []map[string]any{
		{
			"source_id":             "dev-source-01",
			"iface":                 "mock0",
			"windows":               int64(170),
			"rx_bytes":              uint64(158000000),
			"rx_packets":            uint64(98000),
			"rx_dropped":            uint64(0),
			"rx_errors":             uint64(0),
			"tx_bytes":              uint64(12000000),
			"tx_packets":            uint64(9000),
			"tx_dropped":            uint64(0),
			"tx_errors":             uint64(0),
			"packet_queue_len":      uint64(18),
			"packet_queue_capacity": uint64(10000),
			"window_queue_len":      uint64(0),
			"window_queue_capacity": uint64(32),
			"first_window_ts":       now - int64(minutes*60),
			"latest_window_ts":      now - 5,
			"freshness_seconds":     int64(5),
			"drop_ratio":            0.0,
			"error_ratio":           0.0,
			"packet_queue_pressure": 0.0018,
			"window_queue_pressure": 0.0,
			"queue_pressure":        0.0018,
			"status":                "healthy",
		},
	}
	return map[string]any{
		"generated_at": now,
		"minutes":      minutes,
		"status":       "healthy",
		"summary": map[string]any{
			"windows":          int64(170),
			"rx_bytes":         uint64(158000000),
			"rx_packets":       uint64(98000),
			"rx_dropped":       uint64(0),
			"rx_errors":        uint64(0),
			"tx_bytes":         uint64(12000000),
			"tx_packets":       uint64(9000),
			"tx_dropped":       uint64(0),
			"tx_errors":        uint64(0),
			"packet_queue_len": uint64(18),
			"window_queue_len": uint64(0),
			"queue_pressure":   0.0018,
			"drop_ratio":       0.0,
			"error_ratio":      0.0,
			"source_count":     len(sources),
			"interface_count":  1,
			"latest_window_ts": now - 5,
		},
		"sources": sources,
		"recommendations": []map[string]string{
			{"level": "info", "title": "采集接口健康", "detail": "当前未发现接口丢包或错误增量"},
		},
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

func demoAuditEvents() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{
			"id":          "audit-demo-collector",
			"ts":          now - 180,
			"actor":       "operator",
			"action":      "collector.config.update",
			"target":      "dev-collector-01",
			"summary":     "更新采集器配置：live_pcap / eth0",
			"detail":      `{"mode":"live_pcap","iface":"eth0","session_topn":500}`,
			"detail_text": `{"mode":"live_pcap","iface":"eth0","session_topn":500}`,
			"client_ip":   "127.0.0.1",
		},
		{
			"id":          "audit-demo-rule",
			"ts":          now - 420,
			"actor":       "operator",
			"action":      "detection_rule.upsert",
			"target":      "rule-external-session-burst",
			"summary":     "保存检测规则：公网会话突增",
			"detail":      `{"metric":"external_sessions","threshold":30}`,
			"detail_text": `{"metric":"external_sessions","threshold":30}`,
			"client_ip":   "127.0.0.1",
		},
	}
}

func demoConfigVersions() []map[string]any {
	now := time.Now().Unix()
	collectorConfig := `{"mode":"live_pcap","iface":"eth0","source_id":"live_pcap-eth0","bpf_filter":"ip or ip6","session_topn":500}`
	alertConfig := `{"flow_bytes":20480,"flow_share":0.3,"source_packets":50,"link_utilization":0.8,"silenced_subjects":["dst_port:22"]}`
	return []map[string]any{
		{
			"id":          "cfg-demo-collector",
			"ts":          now - 180,
			"actor":       "operator",
			"scope":       "collector",
			"target":      "dev-collector-01",
			"action":      "collector.config.update",
			"summary":     "更新采集器配置：live_pcap / eth0",
			"config":      collectorConfig,
			"config_text": collectorConfig,
			"client_ip":   "127.0.0.1",
		},
		{
			"id":          "cfg-demo-alerts",
			"ts":          now - 420,
			"actor":       "operator",
			"scope":       "alerts",
			"target":      "dev-collector-01",
			"action":      "alert.silence.add",
			"summary":     "加入白名单/静默名单：dst_port:22",
			"config":      alertConfig,
			"config_text": alertConfig,
			"client_ip":   "127.0.0.1",
		},
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

func demoServiceAnalytics(minutes int) map[string]any {
	now := time.Now().Unix()
	services := []model.TopItem{
		{Key: "HTTPS", Bytes: 88000000, Packets: 48000},
		{Key: "SSH", Bytes: 18000000, Packets: 7200},
		{Key: "DNS", Bytes: 5000000, Packets: 12000},
	}
	categories := []model.TopItem{
		{Key: "Web", Bytes: 88000000, Packets: 48000},
		{Key: "远程管理", Bytes: 18000000, Packets: 7200},
		{Key: "基础网络", Bytes: 5000000, Packets: 12000},
	}
	risks := []model.TopItem{
		{Key: "low", Bytes: 93000000, Packets: 60000},
		{Key: "high", Bytes: 18000000, Packets: 7200},
	}
	details := []map[string]any{
		{"service": "HTTPS", "category": "Web", "risk": "low", "bytes": uint64(88000000), "packets": uint64(48000), "client_count": uint64(7), "server_count": uint64(3), "session_count": uint64(14), "top_port": "443/tcp", "sample_flow": "10.10.1.42:53210 -> 172.20.2.10:443 / tcp", "first_seen": now - int64(minutes*60), "last_seen": now},
		{"service": "SSH", "category": "远程管理", "risk": "high", "bytes": uint64(18000000), "packets": uint64(7200), "client_count": uint64(2), "server_count": uint64(1), "session_count": uint64(3), "top_port": "22/tcp", "sample_flow": "10.10.1.77:53192 -> 172.20.2.81:22 / tcp", "first_seen": now - 600, "last_seen": now - 10},
	}
	return map[string]any{
		"generated_at": now,
		"minutes":      minutes,
		"summary": map[string]any{
			"service_count":      len(services),
			"category_count":     len(categories),
			"high_risk_services": int64(1),
			"total_bytes":        uint64(111000000),
			"total_packets":      uint64(67200),
			"top_service":        "HTTPS",
			"top_risk":           "low",
		},
		"services":   services,
		"categories": categories,
		"risks":      risks,
		"growth": []map[string]any{
			{"dimension": "service", "key": "HTTPS", "current_bytes": uint64(88000000), "previous_bytes": uint64(52000000), "delta_bytes": int64(36000000), "current_packets": uint64(48000), "previous_packets": uint64(31000), "delta_packets": int64(17000), "change_ratio": 0.69},
			{"dimension": "service", "key": "SSH", "current_bytes": uint64(18000000), "previous_bytes": uint64(0), "delta_bytes": int64(18000000), "current_packets": uint64(7200), "previous_packets": uint64(0), "delta_packets": int64(7200), "change_ratio": 0},
		},
		"ports": []map[string]any{
			{"service": "HTTPS", "port": "443", "protocol": "tcp", "category": "Web", "risk": "low", "bytes": uint64(88000000), "packets": uint64(48000), "sample_flow": "10.10.1.42:53210 -> 172.20.2.10:443 / tcp", "last_seen": now},
			{"service": "SSH", "port": "22", "protocol": "tcp", "category": "远程管理", "risk": "high", "bytes": uint64(18000000), "packets": uint64(7200), "sample_flow": "10.10.1.77:53192 -> 172.20.2.81:22 / tcp", "last_seen": now - 10},
		},
		"details": details,
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

func demoAssetRiskPosture() []map[string]any {
	now := time.Now().Unix()
	return []map[string]any{
		{
			"ip":                 "10.2.0.12",
			"name":               "示例 Web 服务",
			"owner":              "平台团队",
			"business":           "NexaFlow",
			"environment":        "测试",
			"criticality":        "high",
			"role":               "服务端",
			"risk_score":         int64(86),
			"risk_level":         "critical",
			"total_bytes":        uint64(96000000),
			"total_packets":      uint64(42000),
			"external_bytes":     uint64(36000000),
			"external_peers":     int64(2),
			"external_sessions":  int64(44),
			"exposed_services":   int64(3),
			"high_risk_services": int64(1),
			"open_incidents":     int64(2),
			"critical_incidents": int64(1),
			"anomaly_count":      int64(1),
			"top_finding":        "事件：公网对端在 15 分钟内对内部资产单端口建立 40 条会话",
			"recommended_action": "优先核对公网暴露和高危服务，确认访问来源、负责人和白名单策略",
			"last_seen":          now,
			"top_finding_score":  int64(86),
		},
		{
			"ip":                 "10.10.1.42",
			"name":               "",
			"owner":              "",
			"business":           "",
			"environment":        "未分类",
			"criticality":        "normal",
			"role":               "外联源",
			"risk_score":         int64(58),
			"risk_level":         "warning",
			"total_bytes":        uint64(80000000),
			"total_packets":      uint64(25000),
			"external_bytes":     uint64(12000000),
			"external_peers":     int64(4),
			"external_sessions":  int64(12),
			"exposed_services":   int64(0),
			"high_risk_services": int64(0),
			"open_incidents":     int64(1),
			"critical_incidents": int64(0),
			"anomaly_count":      int64(0),
			"top_finding":        "事件：单会话占近 15 分钟总流量 32.0%",
			"recommended_action": "检查资产归属和流量用途，补齐负责人、业务标签和白名单判断",
			"last_seen":          now,
			"top_finding_score":  int64(58),
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
		{
			"kind":     "external_session_burst",
			"severity": "warning",
			"subject":  "211.93.22.130 -> 10.2.0.12",
			"summary":  "公网对端在 15 分钟内对内部资产单端口建立 40 条会话",
			"bytes":    uint64(7000000),
			"packets":  uint64(6800),
			"score":    80,
		},
	}
}

func demoSecurityIncidents(now int64) []map[string]any {
	return []map[string]any{
		{
			"id":                 "insight:external_session_burst:211.93.22.130 -> 10.2.0.12",
			"source":             "风险线索",
			"category":           "公网暴露",
			"kind":               "external_session_burst",
			"severity":           "warning",
			"status":             "open",
			"subject":            "211.93.22.130 -> 10.2.0.12",
			"summary":            "公网对端在 15 分钟内对内部资产单端口建立 40 条会话",
			"bytes":              uint64(7000000),
			"packets":            uint64(6800),
			"score":              80,
			"first_seen":         now - 900,
			"last_seen":          now,
			"recommended_action": "核对公网来源、服务用途和防火墙访问策略，必要时加入白名单或限制来源",
		},
		{
			"id":                 "anomaly:service:SSH",
			"source":             "异常波动",
			"category":           "新增对象",
			"kind":               "new_dimension",
			"severity":           "critical",
			"status":             "open",
			"subject":            "service:SSH",
			"summary":            "应用服务 SSH 近 15 分钟新出现流量 18.00 MB",
			"bytes":              uint64(18000000),
			"packets":            uint64(7200),
			"score":              88,
			"first_seen":         now - 900,
			"last_seen":          now,
			"recommended_action": "确认新增服务是否符合变更计划，检查关联资产、端口画像和会话明细",
		},
	}
}

func demoTrafficAnomalies() []map[string]any {
	return []map[string]any{
		{
			"kind":             "link_burst",
			"dimension":        "link",
			"key":              "链路总流量",
			"severity":         "warning",
			"summary":          "近 15 分钟链路总流量较上一周期增长 +85.0%",
			"current_bytes":    uint64(158000000),
			"baseline_bytes":   uint64(85000000),
			"delta_bytes":      int64(73000000),
			"current_packets":  uint64(98000),
			"baseline_packets": uint64(54000),
			"delta_packets":    int64(44000),
			"change_ratio":     0.85,
			"score":            72,
		},
		{
			"kind":             "new_dimension",
			"dimension":        "service",
			"key":              "SSH",
			"severity":         "critical",
			"summary":          "应用服务 SSH 近 15 分钟新出现流量 18.00 MB",
			"current_bytes":    uint64(18000000),
			"baseline_bytes":   uint64(0),
			"delta_bytes":      int64(18000000),
			"current_packets":  uint64(7200),
			"baseline_packets": uint64(0),
			"delta_packets":    int64(7200),
			"change_ratio":     999.0,
			"score":            88,
		},
	}
}

func demoReportOverview(minutes int) map[string]any {
	now := time.Now().Unix()
	assetRisks := demoAssetRiskPosture()
	incidents := demoSecurityIncidents(now)
	anomalies := demoTrafficAnomalies()
	exposures := demoServiceExposure()
	return map[string]any{
		"generated_at": now,
		"minutes":      minutes,
		"summary": map[string]any{
			"minutes":              minutes,
			"bytes":                uint64(158000000),
			"packets":              uint64(98000),
			"utilization":          0.08,
			"asset_count":          len(assetRisks),
			"critical_assets":      1,
			"open_incidents":       len(incidents),
			"critical_incidents":   1,
			"anomaly_count":        len(anomalies),
			"critical_anomalies":   1,
			"exposed_services":     len(exposures),
			"high_risk_services":   1,
			"external_access":      2,
			"external_session_sum": int64(48),
			"avg_mbps":             7.68,
			"peak_mbps":            25.6,
			"p95_mbps":             19.2,
		},
		"asset_risks":     assetRisks,
		"incidents":       incidents,
		"anomalies":       anomalies,
		"exposures":       exposures,
		"external_access": demoExternalAccess(),
		"top_src":         []model.TopItem{{Key: "10.2.0.12", Bytes: 96000000, Packets: 42000}},
		"top_ports":       []model.TopItem{{Key: "8081", Bytes: 36000000, Packets: 18000}},
		"top_services":    []model.TopItem{{Key: "HTTP Alternate", Bytes: 36000000, Packets: 18000}},
		"recommendations": []map[string]string{
			{"level": "critical", "title": "优先处置严重资产", "detail": "10.2.0.12 存在公网访问、事件和高风险服务，需要确认暴露策略"},
			{"level": "warning", "title": "补齐资产归属", "detail": "未归属资产需要补充负责人和业务标签，便于后续事件流转"},
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

func demoCapacityPlanning(minutes int, bandwidthMbps uint64) map[string]any {
	now := time.Now().Unix()
	if bandwidthMbps == 0 {
		bandwidthMbps = 1000
	}
	return map[string]any{
		"generated_at": now,
		"minutes":      minutes,
		"summary": map[string]any{
			"minutes":             minutes,
			"bandwidth_mbps":      bandwidthMbps,
			"avg_mbps":            7.68,
			"peak_mbps":           25.6,
			"p95_mbps":            19.2,
			"previous_peak_mbps":  18.4,
			"growth_mbps":         7.2,
			"growth_ratio":        0.39,
			"headroom_mbps":       float64(bandwidthMbps) - 25.6,
			"headroom_ratio":      ratio(float64(bandwidthMbps)-25.6, float64(bandwidthMbps)),
			"peak_utilization":    ratio(25.6, float64(bandwidthMbps)),
			"p95_utilization":     ratio(19.2, float64(bandwidthMbps)),
			"saturation_eta_mins": 9999.0,
			"risk_level":          "healthy",
		},
		"trend": []map[string]any{
			{"ts": now - 180, "bytes": uint64(24000000), "packets": uint64(9300), "utilization": 0.02, "mbps": 3.2},
			{"ts": now - 120, "bytes": uint64(36000000), "packets": uint64(12000), "utilization": 0.03, "mbps": 4.8},
			{"ts": now - 60, "bytes": uint64(52000000), "packets": uint64(18000), "utilization": 0.04, "mbps": 6.93},
		},
		"top_src_growth": []map[string]any{
			{"dimension": "src_ip", "key": "10.10.1.42", "current_bytes": uint64(68000000), "previous_bytes": uint64(22000000), "delta_bytes": int64(46000000), "current_packets": uint64(21000), "previous_packets": uint64(9000), "delta_packets": int64(12000), "change_ratio": 2.09},
		},
		"top_port_growth": []map[string]any{
			{"dimension": "dst_port", "key": "443", "current_bytes": uint64(88000000), "previous_bytes": uint64(52000000), "delta_bytes": int64(36000000), "current_packets": uint64(48000), "previous_packets": uint64(31000), "delta_packets": int64(17000), "change_ratio": 0.69},
		},
		"top_service_growth": []map[string]any{
			{"dimension": "service", "key": "HTTPS", "current_bytes": uint64(88000000), "previous_bytes": uint64(52000000), "delta_bytes": int64(36000000), "current_packets": uint64(48000), "previous_packets": uint64(31000), "delta_packets": int64(17000), "change_ratio": 0.69},
		},
		"recommendations": []map[string]string{
			{"level": "info", "title": "容量余量充足", "detail": "当前峰值和 P95 吞吐低于带宽阈值，可继续观察增长趋势"},
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

func serviceAnalyticsFromSessions(sessions []map[string]any, limit int) ([]map[string]any, []map[string]any) {
	ports := map[string]map[string]any{}
	details := map[string]map[string]any{}
	clients := map[string]map[string]bool{}
	servers := map[string]map[string]bool{}
	for _, session := range sessions {
		parsed, ok := parseFlowKey(stringValue(session["key"]))
		if !ok {
			continue
		}
		service := identifyService(parsed.DstPort, parsed.Proto)
		bytes := uintValue(session["bytes"])
		packets := uintValue(session["packets"])
		portKey := service.Name + "|" + parsed.DstPort + "|" + parsed.Proto
		portRow := ports[portKey]
		if portRow == nil {
			portRow = map[string]any{
				"service":     service.Name,
				"port":        parsed.DstPort,
				"protocol":    parsed.Proto,
				"category":    service.Category,
				"risk":        service.Risk,
				"bytes":       uint64(0),
				"packets":     uint64(0),
				"sample_flow": stringValue(session["key"]),
			}
		}
		portRow["bytes"] = uintValue(portRow["bytes"]) + bytes
		portRow["packets"] = uintValue(portRow["packets"]) + packets
		if int64Value(session["last_seen"]) >= int64Value(portRow["last_seen"]) {
			portRow["last_seen"] = int64Value(session["last_seen"])
			portRow["sample_flow"] = stringValue(session["key"])
		}
		ports[portKey] = portRow

		detail := details[service.Name]
		if detail == nil {
			detail = map[string]any{
				"service":       service.Name,
				"category":      service.Category,
				"risk":          service.Risk,
				"bytes":         uint64(0),
				"packets":       uint64(0),
				"client_count":  uint64(0),
				"server_count":  uint64(0),
				"session_count": uint64(0),
				"top_port":      parsed.DstPort + "/" + parsed.Proto,
				"sample_flow":   stringValue(session["key"]),
				"first_seen":    int64Value(session["first_seen"]),
				"last_seen":     int64Value(session["last_seen"]),
			}
			clients[service.Name] = map[string]bool{}
			servers[service.Name] = map[string]bool{}
		}
		detail["bytes"] = uintValue(detail["bytes"]) + bytes
		detail["packets"] = uintValue(detail["packets"]) + packets
		detail["session_count"] = uintValue(detail["session_count"]) + 1
		clients[service.Name][parsed.SrcIP] = true
		servers[service.Name][parsed.DstIP] = true
		detail["client_count"] = uint64(len(clients[service.Name]))
		detail["server_count"] = uint64(len(servers[service.Name]))
		if first := int64Value(session["first_seen"]); first > 0 && (int64Value(detail["first_seen"]) == 0 || first < int64Value(detail["first_seen"])) {
			detail["first_seen"] = first
		}
		if last := int64Value(session["last_seen"]); last >= int64Value(detail["last_seen"]) {
			detail["last_seen"] = last
			detail["sample_flow"] = stringValue(session["key"])
			detail["top_port"] = parsed.DstPort + "/" + parsed.Proto
		}
		details[service.Name] = detail
	}
	return sortedMapRows(ports, limit, func(row map[string]any) int {
			if riskWeight(stringValue(row["risk"])) != 0 {
				return riskWeight(stringValue(row["risk"])) * 1_000_000_000
			}
			return 0
		}), sortedMapRows(details, limit, func(row map[string]any) int {
			return riskWeight(stringValue(row["risk"])) * 1_000_000_000
		})
}

func serviceAnalyticsSummary(services, categories, risks []model.TopItem, details []map[string]any) map[string]any {
	totalBytes := uint64(0)
	totalPackets := uint64(0)
	for _, service := range services {
		totalBytes += service.Bytes
		totalPackets += service.Packets
	}
	highRiskServices := int64(0)
	for _, detail := range details {
		if riskWeight(stringValue(detail["risk"])) >= riskWeight("high") {
			highRiskServices++
		}
	}
	return map[string]any{
		"service_count":      len(services),
		"category_count":     len(uniqueTopKeys(categories)),
		"high_risk_services": highRiskServices,
		"total_bytes":        totalBytes,
		"total_packets":      totalPackets,
		"top_service":        topItemKey(services),
		"top_risk":           topItemKey(risks),
	}
}

func sortedMapRows(rows map[string]map[string]any, limit int, priority func(map[string]any) int) []map[string]any {
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, row)
	}
	sort.Slice(items, func(i, j int) bool {
		if priority(items[i]) != priority(items[j]) {
			return priority(items[i]) > priority(items[j])
		}
		if uintValue(items[i]["bytes"]) != uintValue(items[j]["bytes"]) {
			return uintValue(items[i]["bytes"]) > uintValue(items[j]["bytes"])
		}
		return stringValue(items[i]["service"]) < stringValue(items[j]["service"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func uniqueTopKeys(items []model.TopItem) []string {
	keys := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		if !seen[item.Key] {
			keys = append(keys, item.Key)
			seen[item.Key] = true
		}
	}
	return keys
}

func topItemKey(items []model.TopItem) string {
	if len(items) == 0 {
		return "-"
	}
	return items[0].Key
}

func incidentFromAlert(alert model.AlertEvent) map[string]any {
	return map[string]any{
		"id":                 "alert:" + alert.ID,
		"source":             "阈值告警",
		"category":           "阈值",
		"kind":               "threshold_alert",
		"severity":           alert.Severity,
		"status":             alert.Status,
		"subject":            alert.Subject,
		"summary":            alert.Summary,
		"bytes":              uint64(0),
		"packets":            uint64(0),
		"score":              severityScore(alert.Severity),
		"first_seen":         alert.FirstSeen,
		"last_seen":          alert.LastSeen,
		"recommended_action": "确认阈值是否符合当前链路基线，查看相关 TopN、画像和会话明细",
	}
}

func incidentFromInsight(row map[string]any, now int64, minutes int) map[string]any {
	kind := stringValue(row["kind"])
	severity := stringValue(row["severity"])
	subject := stringValue(row["subject"])
	score := int64Value(row["score"])
	if score == 0 {
		score = int64(severityScore(severity))
	}
	return map[string]any{
		"id":                 "insight:" + kind + ":" + subject,
		"source":             "风险线索",
		"category":           incidentInsightCategory(kind),
		"kind":               kind,
		"severity":           severity,
		"status":             "open",
		"subject":            subject,
		"summary":            row["summary"],
		"bytes":              uintValue(row["bytes"]),
		"packets":            uintValue(row["packets"]),
		"score":              score,
		"first_seen":         now - int64(minutes*60),
		"last_seen":          now,
		"recommended_action": recommendedActionForInsight(kind),
	}
}

func incidentFromAnomaly(row map[string]any, now int64, minutes int) map[string]any {
	kind := stringValue(row["kind"])
	dimension := stringValue(row["dimension"])
	key := stringValue(row["key"])
	subject := dimension + ":" + key
	return map[string]any{
		"id":                 "anomaly:" + dimension + ":" + key,
		"source":             "异常波动",
		"category":           incidentAnomalyCategory(kind),
		"kind":               kind,
		"severity":           row["severity"],
		"status":             "open",
		"subject":            subject,
		"summary":            row["summary"],
		"bytes":              uintValue(row["current_bytes"]),
		"packets":            uintValue(row["current_packets"]),
		"score":              int64Value(row["score"]),
		"first_seen":         now - int64(minutes*60),
		"last_seen":          now,
		"recommended_action": recommendedActionForAnomaly(kind, dimension),
	}
}

func incidentInsightCategory(kind string) string {
	switch kind {
	case "external_port_scan", "external_session_burst", "outbound_probe":
		return "公网暴露"
	case "service_risk", "sensitive_port":
		return "高危服务"
	case "fanout":
		return "横向移动"
	case "qos_mark", "ecn_mark":
		return "网络质量"
	default:
		return "流量风险"
	}
}

func incidentAnomalyCategory(kind string) string {
	switch kind {
	case "link_burst":
		return "链路突增"
	case "new_dimension":
		return "新增对象"
	default:
		return "对象突增"
	}
}

func recommendedActionForInsight(kind string) string {
	switch kind {
	case "external_port_scan", "external_session_burst":
		return "核对公网来源、内部资产和端口用途，检查访问控制策略"
	case "outbound_probe":
		return "排查内部主机外联目标，结合会话追踪确认是否为异常扫描或自动化任务"
	case "service_risk", "sensitive_port":
		return "确认高风险服务是否应暴露，检查资产负责人、白名单和访问来源"
	case "fanout":
		return "查看源主机画像和关联目的主机，判断是否存在横向探测"
	case "qos_mark", "ecn_mark":
		return "确认 QoS/ECN 标记是否符合网络策略，排查拥塞或异常标记来源"
	default:
		return "结合对象画像、会话追踪和 TopN 排行继续排查"
	}
}

func recommendedActionForAnomaly(kind, dimension string) string {
	if kind == "link_burst" {
		return "查看链路趋势、TopN 和异常增量排行，确认是否为业务峰值或异常放量"
	}
	if kind == "new_dimension" {
		return "确认新增对象是否符合变更计划，检查资产、端口画像和相关会话"
	}
	if dimension == "dst_port" || dimension == "service" {
		return "检查服务端口、应用服务和访问来源，确认是否出现新增服务或异常访问"
	}
	return "查看对象画像和关联关系，确认流量增长来源与业务背景"
}

func incidentStatusWeight(status string) int {
	switch status {
	case "open":
		return 3
	case "ack":
		return 2
	case "resolved":
		return 1
	default:
		return 0
	}
}

func severityScore(severity string) int {
	switch severity {
	case "critical":
		return 90
	case "warning":
		return 70
	default:
		return 40
	}
}

func applyIncidentStatusOverrides(items []map[string]any, overrides map[string]string) {
	if len(overrides) == 0 {
		return
	}
	for _, item := range items {
		if status := overrides[stringValue(item["id"])]; status != "" {
			item["status"] = status
		}
	}
}

func countMapsByString(rows []map[string]any, key, value string) int64 {
	count := int64(0)
	for _, row := range rows {
		if stringValue(row[key]) == value {
			count++
		}
	}
	return count
}

func countHighRiskRows(rows []map[string]any) int64 {
	count := int64(0)
	for _, row := range rows {
		if riskWeight(stringValue(row["risk"])) >= riskWeight("high") {
			count++
		}
	}
	return count
}

func sumIntMaps(rows []map[string]any, key string) int64 {
	total := int64(0)
	for _, row := range rows {
		total += int64Value(row[key])
	}
	return total
}

func mapValue(row map[string]any, key, nested string) any {
	if row == nil {
		return nil
	}
	child, ok := row[key].(map[string]any)
	if !ok {
		return nil
	}
	return child[nested]
}

func reportRecommendations(metrics map[string]any, assetRisks, incidents, anomalies, exposures []map[string]any) []map[string]string {
	items := []map[string]string{}
	if int64Value(metrics["critical_assets"]) > 0 {
		title := "优先处置严重资产"
		detail := "存在 " + strconv.FormatInt(int64Value(metrics["critical_assets"]), 10) + " 个严重资产，优先核对公网暴露、高危服务和责任人"
		if len(assetRisks) > 0 {
			detail = stringValue(assetRisks[0]["ip"]) + " 风险评分最高：" + stringValue(assetRisks[0]["top_finding"])
		}
		items = append(items, map[string]string{"level": "critical", "title": title, "detail": detail})
	}
	if int64Value(metrics["critical_incidents"]) > 0 {
		items = append(items, map[string]string{"level": "critical", "title": "处理严重事件", "detail": "事件中心存在严重事件，建议先确认、补充处置备注并跟踪恢复状态"})
	}
	if int64Value(metrics["high_risk_services"]) > 0 {
		items = append(items, map[string]string{"level": "warning", "title": "收敛高风险服务", "detail": "服务暴露面存在高风险服务，检查端口用途、访问来源和白名单策略"})
	}
	if int64Value(metrics["critical_anomalies"]) > 0 {
		items = append(items, map[string]string{"level": "warning", "title": "复核异常波动", "detail": "异常波动里存在严重流量变化，结合对象画像和会话追踪确认业务背景"})
	}
	if len(items) == 0 {
		items = append(items, map[string]string{"level": "info", "title": "保持观察", "detail": "当前窗口未发现严重风险，建议继续观察资产风险评分和事件趋势"})
	}
	if len(incidents) == 0 && len(anomalies) == 0 && len(exposures) == 0 {
		items = append(items, map[string]string{"level": "info", "title": "完善数据采集", "detail": "当前报表风险数据较少，可扩大观察窗口或确认采集接口覆盖范围"})
	}
	return items
}

func (s *Store) detectionRuleRows(ctx context.Context, rule model.DetectionRule, minutes, limit int) ([]map[string]any, error) {
	switch rule.Metric {
	case "src_ip_bytes":
		return s.detectionRuleTopNRows(ctx, rule, "ip", "src", minutes, limit)
	case "dst_ip_bytes":
		return s.detectionRuleTopNRows(ctx, rule, "ip", "dst", minutes, limit)
	case "dst_port_bytes":
		return s.detectionRuleTopNRows(ctx, rule, "dst_port", "src", minutes, limit)
	case "service_bytes":
		return s.detectionRuleTopNRows(ctx, rule, "service", "src", minutes, limit)
	case "flow_bytes":
		return s.detectionRuleTopNRows(ctx, rule, "flow", "src", minutes, limit)
	case "link_peak_mbps":
		analysis, err := s.TrafficAnalysis(ctx, minutes)
		row := map[string]any{
			"subject": "链路峰值吞吐",
			"value":   floatValue(mapValue(analysis, "baseline", "peak_mbps")),
			"bytes":   uint64(0),
			"packets": uint64(0),
		}
		return detectionRuleScalarRows(rule, minutes, row, "Mbps"), err
	case "link_utilization":
		summary, err := s.Summary(ctx, minutes)
		row := map[string]any{
			"subject": "链路利用率",
			"value":   floatValue(summary["utilization"]),
			"bytes":   uintValue(summary["bytes"]),
			"packets": uintValue(summary["packets"]),
		}
		return detectionRuleScalarRows(rule, minutes, row, "ratio"), err
	case "external_sessions":
		rows, err := s.ExternalAccess(ctx, minutes, max(limit*4, 80))
		return detectionRuleMapRows(rule, minutes, rows, "session_count", "公网访问", func(row map[string]any) string {
			return stringValue(row["public_ip"]) + " -> " + stringValue(row["internal_ip"]) + ":" + stringValue(row["port"])
		}, "sessions"), err
	case "exposed_clients":
		rows, err := s.ServiceExposure(ctx, minutes, max(limit*4, 80))
		return detectionRuleMapRows(rule, minutes, rows, "client_count", "服务暴露", func(row map[string]any) string {
			return stringValue(row["ip"]) + ":" + stringValue(row["port"]) + " / " + stringValue(row["service"])
		}, "clients"), err
	default:
		return []map[string]any{}, nil
	}
}

func (s *Store) detectionRuleTopNRows(ctx context.Context, rule model.DetectionRule, dimension, direction string, minutes, limit int) ([]map[string]any, error) {
	rows, err := s.TopN(ctx, dimension, direction, max(limit*4, 80), minutes)
	result := []map[string]any{}
	for _, row := range rows {
		item := map[string]any{
			"subject": row.Key,
			"value":   float64(row.Bytes),
			"bytes":   row.Bytes,
			"packets": row.Packets,
		}
		if finding, ok := detectionRuleFinding(rule, minutes, item, "bytes"); ok {
			result = append(result, finding)
		}
		if len(result) >= limit {
			break
		}
	}
	return result, err
}

func detectionRuleScalarRows(rule model.DetectionRule, minutes int, row map[string]any, unit string) []map[string]any {
	if finding, ok := detectionRuleFinding(rule, minutes, row, unit); ok {
		return []map[string]any{finding}
	}
	return []map[string]any{}
}

func detectionRuleMapRows(rule model.DetectionRule, minutes int, rows []map[string]any, valueKey, category string, subjectOf func(map[string]any) string, unit string) []map[string]any {
	result := []map[string]any{}
	for _, row := range rows {
		item := map[string]any{
			"subject":  subjectOf(row),
			"value":    float64(int64Value(row[valueKey])),
			"bytes":    uintValue(row["bytes"]),
			"packets":  uintValue(row["packets"]),
			"category": category,
			"text":     strings.Join(mapStringValues(row), " "),
		}
		if finding, ok := detectionRuleFinding(rule, minutes, item, unit); ok {
			result = append(result, finding)
		}
	}
	return result
}

func detectionRuleFinding(rule model.DetectionRule, minutes int, item map[string]any, unit string) (map[string]any, bool) {
	subject := stringValue(item["subject"])
	if rule.Match != "" {
		text := strings.ToLower(subject + " " + stringValue(item["text"]))
		if !strings.Contains(text, strings.ToLower(rule.Match)) {
			return nil, false
		}
	}
	value := floatValue(item["value"])
	if !compareRuleValue(value, rule.Operator, rule.Threshold) {
		return nil, false
	}
	score := int(math.Min(100, math.Max(1, (value/rule.Threshold)*100)))
	summary := fmt.Sprintf("%s 命中规则：%s，当前值 %s，阈值 %s", subject, rule.Name, formatRuleValue(value, unit), formatRuleValue(rule.Threshold, unit))
	return map[string]any{
		"id":                 "rule:" + rule.ID + ":" + subject,
		"rule_id":            rule.ID,
		"rule_name":          rule.Name,
		"category":           rule.Category,
		"kind":               "custom_rule",
		"metric":             rule.Metric,
		"severity":           rule.Severity,
		"subject":            subject,
		"summary":            summary,
		"value":              value,
		"threshold":          rule.Threshold,
		"unit":               unit,
		"bytes":              uintValue(item["bytes"]),
		"packets":            uintValue(item["packets"]),
		"score":              score,
		"recommended_action": rule.RecommendedAction,
		"matched_at":         time.Now().Unix(),
	}, true
}

func compareRuleValue(value float64, operator string, threshold float64) bool {
	switch operator {
	case "gt":
		return value > threshold
	case "lte":
		return value <= threshold
	case "lt":
		return value < threshold
	case "eq":
		return value == threshold
	default:
		return value >= threshold
	}
}

func formatRuleValue(value float64, unit string) string {
	switch unit {
	case "bytes":
		return formatBytesText(uint64(value))
	case "ratio":
		return fmt.Sprintf("%.2f%%", value*100)
	case "Mbps":
		return fmt.Sprintf("%.2f Mbps", value)
	default:
		return fmt.Sprintf("%.0f %s", value, unit)
	}
}

func mapStringValues(row map[string]any) []string {
	values := []string{}
	for _, value := range row {
		if text := stringValue(value); text != "" {
			values = append(values, text)
		}
	}
	return values
}

func capacityRiskLevel(headroomRatio, growthMbps, etaMinutes float64) string {
	if headroomRatio <= 0.1 || (growthMbps > 0 && etaMinutes > 0 && etaMinutes <= 60) {
		return "critical"
	}
	if headroomRatio <= 0.25 || growthMbps > 0 {
		return "warning"
	}
	return "healthy"
}

func capacityGrowthRows(rows []map[string]any, limit int) []map[string]any {
	result := []map[string]any{}
	for _, row := range rows {
		if int64Value(row["delta_bytes"]) <= 0 {
			continue
		}
		result = append(result, row)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func capacityRecommendations(summary map[string]any, srcGrowth, portGrowth, serviceGrowth []map[string]any) []map[string]string {
	items := []map[string]string{}
	risk := stringValue(summary["risk_level"])
	if risk == "critical" {
		items = append(items, map[string]string{"level": "critical", "title": "容量风险严重", "detail": "峰值带宽余量不足或预计短时间内触顶，建议立即核对 Top 增长对象并评估扩容或限速策略"})
	} else if risk == "warning" {
		items = append(items, map[string]string{"level": "warning", "title": "关注容量增长", "detail": "链路峰值或带宽余量出现压力，建议结合增长最快的源 IP、端口和服务确认是否为计划内流量"})
	} else {
		items = append(items, map[string]string{"level": "info", "title": "容量余量充足", "detail": "当前峰值和 P95 吞吐低于带宽阈值，可继续观察增长趋势"})
	}
	if len(srcGrowth) > 0 && int64Value(srcGrowth[0]["delta_bytes"]) > 0 {
		items = append(items, map[string]string{"level": "warning", "title": "定位增长源 IP", "detail": stringValue(srcGrowth[0]["key"]) + " 是当前增长最快源 IP，增长 " + formatBytesText(uint64(int64Value(srcGrowth[0]["delta_bytes"])))})
	}
	if len(portGrowth) > 0 && int64Value(portGrowth[0]["delta_bytes"]) > 0 {
		items = append(items, map[string]string{"level": "info", "title": "核对增长端口", "detail": "目的端口 " + stringValue(portGrowth[0]["key"]) + " 增长最明显，建议确认是否符合业务变更"})
	}
	if len(serviceGrowth) > 0 && int64Value(serviceGrowth[0]["delta_bytes"]) > 0 {
		items = append(items, map[string]string{"level": "info", "title": "核对增长服务", "detail": stringValue(serviceGrowth[0]["key"]) + " 是增长最快服务，建议结合会话追踪排查来源"})
	}
	return items
}

func (s *Store) dataQualitySources(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    source_id,
    iface,
    count() AS windows,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(drops) AS drops,
    max(utilization) AS max_utilization,
    toUnixTimestamp(min(ts)) AS first_window_ts,
    toUnixTimestamp(max(ts)) AS latest_window_ts
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
GROUP BY source_id, iface
ORDER BY latest_window_ts DESC, bytes DESC
LIMIT %d
FORMAT JSON`, s.database, minutes, limit)
	body, err := s.query(ctx, q)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	return parsed.Data, nil
}

func (s *Store) dataQualityGaps(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	q := fmt.Sprintf(`SELECT
    source_id,
    iface,
    toUnixTimestamp(ts) AS window_ts
FROM %s.link_traffic_5s
WHERE ts >= now() - INTERVAL %d MINUTE
ORDER BY source_id ASC, iface ASC, ts ASC
LIMIT 5000
FORMAT JSON`, s.database, minutes)
	body, err := s.query(ctx, q)
	if err != nil {
		return []map[string]any{}, err
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return []map[string]any{}, err
	}
	items := []map[string]any{}
	lastKey := ""
	lastTs := int64(0)
	for _, row := range parsed.Data {
		key := stringValue(row["source_id"]) + "|" + stringValue(row["iface"])
		ts := int64Value(row["window_ts"])
		if key == lastKey && lastTs > 0 && ts-lastTs > 10 {
			duration := ts - lastTs
			items = append(items, map[string]any{
				"source_id":        stringValue(row["source_id"]),
				"iface":            stringValue(row["iface"]),
				"start_ts":         lastTs,
				"end_ts":           ts,
				"duration_seconds": duration,
				"missing_windows":  max(int(duration/5)-1, 1),
			})
		}
		lastKey = key
		lastTs = ts
	}
	sort.Slice(items, func(i, j int) bool {
		return int64Value(items[i]["duration_seconds"]) > int64Value(items[j]["duration_seconds"])
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func dataQualitySourceStatus(freshness int64, coverage float64, drops uint64) string {
	if freshness > 30 || coverage < 0.5 {
		return "critical"
	}
	if freshness > 12 || coverage < 0.9 || drops > 0 {
		return "warning"
	}
	return "healthy"
}

func dataQualityStatus(freshness int64, coverage float64, gapCount int, staleSources int64) string {
	if freshness > 30 || coverage < 0.5 || staleSources > 0 && coverage < 0.7 {
		return "critical"
	}
	if freshness > 12 || coverage < 0.9 || gapCount > 0 || staleSources > 0 {
		return "warning"
	}
	return "healthy"
}

func dataQualityRecommendations(status string, summary map[string]any, sources, gaps []map[string]any) []map[string]string {
	items := []map[string]string{}
	if status == "healthy" {
		items = append(items, map[string]string{"level": "info", "title": "采集质量稳定", "detail": "当前窗口覆盖率和最新窗口延迟正常，可以继续基于实时数据分析"})
	}
	if int64Value(summary["freshness_seconds"]) > 12 {
		items = append(items, map[string]string{"level": "critical", "title": "检查采集延迟", "detail": "最近采集窗口延迟偏高，优先检查 collector 容器、网卡权限和 ClickHouse 写入"})
	}
	if floatValue(summary["coverage_ratio"]) < 0.9 {
		items = append(items, map[string]string{"level": "warning", "title": "补查窗口覆盖率", "detail": "观察范围内采集窗口覆盖不足，建议核对采集进程是否重启或网卡流量是否中断"})
	}
	if len(gaps) > 0 {
		first := gaps[0]
		items = append(items, map[string]string{"level": "warning", "title": "定位采集断档", "detail": stringValue(first["source_id"]) + " / " + stringValue(first["iface"]) + " 存在最长 " + strconv.FormatInt(int64Value(first["duration_seconds"]), 10) + " 秒断档"})
	}
	for _, source := range sources {
		if uintValue(source["drops"]) > 0 {
			items = append(items, map[string]string{"level": "warning", "title": "关注丢包计数", "detail": stringValue(source["source_id"]) + " / " + stringValue(source["iface"]) + " 存在采集 drops，建议检查网卡负载或抓包权限"})
			break
		}
	}
	if len(items) == 0 {
		items = append(items, map[string]string{"level": "info", "title": "继续观察", "detail": "当前数据质量未出现明显异常"})
	}
	return items
}

func captureQualityRowStatus(row map[string]any) string {
	if uintValue(row["rx_errors"])+uintValue(row["tx_errors"]) > 0 || floatValue(row["error_ratio"]) > 0.001 {
		return "critical"
	}
	if floatValue(row["queue_pressure"]) >= 0.90 {
		return "critical"
	}
	if uintValue(row["rx_dropped"])+uintValue(row["tx_dropped"]) > 0 || floatValue(row["drop_ratio"]) > 0.001 || floatValue(row["queue_pressure"]) >= 0.70 || int64Value(row["freshness_seconds"]) > 12 {
		return "warning"
	}
	return "healthy"
}

func captureQualityStatus(sources []map[string]any) string {
	status := "healthy"
	for _, source := range sources {
		rowStatus := stringValue(source["status"])
		if rowStatus == "critical" {
			return "critical"
		}
		if rowStatus == "warning" {
			status = "warning"
		}
	}
	return status
}

func captureQualityRecommendations(status string, summary map[string]any, sources []map[string]any) []map[string]string {
	items := []map[string]string{}
	if status == "healthy" {
		items = append(items, map[string]string{"level": "info", "title": "采集链路稳定", "detail": "当前网卡 RX/TX 丢包、错误计数和用户态队列积压未出现明显异常"})
	}
	if uintValue(summary["rx_errors"])+uintValue(summary["tx_errors"]) > 0 {
		items = append(items, map[string]string{"level": "critical", "title": "检查接口错误", "detail": "观察窗口内出现 RX/TX errors，建议检查网卡链路、驱动、交换机端口和物理连接"})
	}
	if uintValue(summary["rx_dropped"])+uintValue(summary["tx_dropped"]) > 0 {
		items = append(items, map[string]string{"level": "warning", "title": "检查接口丢包", "detail": "观察窗口内出现 RX/TX dropped，建议核对镜像口流量、容器权限、CPU 和采集处理能力"})
	}
	if floatValue(summary["queue_pressure"]) >= 0.70 {
		items = append(items, map[string]string{"level": "warning", "title": "关注用户态队列积压", "detail": "采集或聚合队列占用超过 70%，建议提升 collector CPU、扩大队列容量或降低采集过滤范围"})
	}
	for _, source := range sources {
		if stringValue(source["status"]) != "healthy" {
			items = append(items, map[string]string{"level": "warning", "title": "定位异常网卡", "detail": stringValue(source["source_id"]) + " / " + stringValue(source["iface"]) + " 采集质量异常，优先查看该接口统计"})
			break
		}
	}
	if len(items) == 0 {
		items = append(items, map[string]string{"level": "info", "title": "继续观察", "detail": "当前采集接口未出现丢包或错误增量"})
	}
	return items
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func countDistinctStrings(rows []map[string]any, key string) int {
	seen := map[string]bool{}
	for _, row := range rows {
		value := stringValue(row[key])
		if value != "" {
			seen[value] = true
		}
	}
	return len(seen)
}

func ratioFloat(value, total float64) float64 {
	if total <= 0 {
		return 0
	}
	result := value / total
	if result > 1 {
		return 1
	}
	if result < 0 {
		return 0
	}
	return result
}

func incidentContextSelector(subject, kind string) map[string]string {
	subject = strings.TrimSpace(subject)
	selector := map[string]string{
		"dimension": "flow",
		"key":       subject,
		"query":     subject,
		"direction": "src",
	}
	if subject == "" {
		return selector
	}
	prefix, value, hasPrefix := strings.Cut(subject, ":")
	if hasPrefix {
		value = strings.TrimSpace(value)
		switch prefix {
		case "src_ip", "dst_ip", "ip":
			selector["dimension"] = "ip"
			selector["key"] = value
			selector["query"] = value
			if prefix == "dst_ip" {
				selector["direction"] = "dst"
			}
			return selector
		case "dst_port":
			selector["dimension"] = "dst_port"
			selector["key"] = value
			selector["query"] = ":" + value + " /"
			return selector
		case "service", "protocol", "flow", "pair":
			selector["dimension"] = prefix
			selector["key"] = value
			selector["query"] = value
			return selector
		case "link":
			selector["dimension"] = "link"
			selector["key"] = value
			selector["query"] = ""
			return selector
		}
	}
	if strings.Contains(subject, " -> ") && strings.Contains(subject, " / ") {
		selector["dimension"] = "flow"
		selector["key"] = subject
		selector["query"] = subject
		return selector
	}
	if strings.Contains(subject, " -> ") {
		selector["dimension"] = "pair"
		selector["key"] = subject
		selector["query"] = subject
		return selector
	}
	if port := subjectPort(subject); port != "" {
		selector["dimension"] = "dst_port"
		selector["key"] = port
		selector["query"] = ":" + port + " /"
		return selector
	}
	if ip := firstIPInText(subject); ip != "" {
		selector["dimension"] = "ip"
		selector["key"] = ip
		selector["query"] = ip
		return selector
	}
	if kind == "link_burst" {
		selector["dimension"] = "link"
		selector["key"] = "链路总流量"
		selector["query"] = ""
	}
	return selector
}

func (s *Store) incidentRelatedInsights(ctx context.Context, dimension, key, query string, minutes, limit int) ([]map[string]any, error) {
	if dimension != "" && dimension != "link" {
		rows, err := s.relatedSecurityInsights(ctx, dimension, key, minutes, limit)
		if len(rows) > 0 || err != nil {
			return rows, err
		}
	}
	rows, err := s.SecurityInsights(ctx, minutes, max(limit*3, 30))
	return filterMapsByText(rows, []string{key, query}, limit), err
}

func (s *Store) incidentRelatedAnomalies(ctx context.Context, dimension, key, query string, minutes, limit int) ([]map[string]any, error) {
	rows, err := s.TrafficAnomalies(ctx, minutes, max(limit*3, 30))
	markers := []string{key, query, dimension + ":" + key}
	filtered := make([]map[string]any, 0, limit)
	for _, row := range rows {
		text := strings.Join([]string{
			stringValue(row["dimension"]),
			stringValue(row["key"]),
			stringValue(row["summary"]),
		}, " ")
		for _, marker := range markers {
			if marker != "" && strings.Contains(text, marker) {
				filtered = append(filtered, row)
				break
			}
		}
		if len(filtered) >= limit {
			break
		}
	}
	if len(filtered) == 0 && dimension == "link" {
		for _, row := range rows {
			if stringValue(row["dimension"]) == "link" {
				filtered = append(filtered, row)
			}
			if len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, err
}

func filterMapsByText(rows []map[string]any, markers []string, limit int) []map[string]any {
	if limit <= 0 {
		limit = len(rows)
	}
	filtered := make([]map[string]any, 0, limit)
	for _, row := range rows {
		text := strings.Join([]string{
			stringValue(row["subject"]),
			stringValue(row["summary"]),
			stringValue(row["kind"]),
		}, " ")
		for _, marker := range markers {
			if marker != "" && strings.Contains(text, marker) {
				filtered = append(filtered, row)
				break
			}
		}
		if len(filtered) >= limit {
			break
		}
	}
	return filtered
}

func incidentPlaybookActions(kind, dimension string) []map[string]string {
	actions := []map[string]string{
		{"label": "查看对象画像", "description": "核对收发方向、最近出现时间、关联主机对和会话排行"},
		{"label": "检查白名单", "description": "确认对象是否为已知业务、维护窗口或可信来源"},
		{"label": "复核访问策略", "description": "对公网、高危服务或新增服务检查防火墙和 ACL 策略"},
	}
	if kind == "outbound_probe" || kind == "fanout" {
		actions = append(actions, map[string]string{"label": "排查横向移动", "description": "查看源主机关联目的、端口扩散和短时会话数量"})
	}
	if kind == "link_burst" || dimension == "link" {
		actions = append(actions, map[string]string{"label": "确认业务峰值", "description": "对照链路趋势、TopN 和变更窗口确认是否为正常流量放量"})
	}
	if dimension == "dst_port" || dimension == "service" {
		actions = append(actions, map[string]string{"label": "确认服务归属", "description": "核对资产负责人、服务用途、暴露方向和客户端来源"})
	}
	return actions
}

func subjectPort(subject string) string {
	if strings.HasPrefix(subject, "dst_port:") {
		return strings.TrimPrefix(subject, "dst_port:")
	}
	return ""
}

func firstIPInText(text string) string {
	normalized := strings.NewReplacer(":", " ", "/", " ", ">", " ", "-", " ", ",", " ", "(", " ", ")", " ").Replace(text)
	for _, token := range strings.Fields(normalized) {
		if addr, err := netip.ParseAddr(token); err == nil {
			return addr.String()
		}
	}
	return ""
}

func anomalyFromChange(row map[string]any, minutes int) (map[string]any, bool) {
	currentBytes := uintValue(row["current_bytes"])
	previousBytes := uintValue(row["previous_bytes"])
	deltaBytes := int64Value(row["delta_bytes"])
	ratioValue := floatValue(row["change_ratio"])
	if deltaBytes <= 0 {
		return nil, false
	}
	if previousBytes > 0 && ratioValue < 0.8 && deltaBytes < int64(10*1024*1024) {
		return nil, false
	}
	if previousBytes == 0 && currentBytes < 2*1024*1024 {
		return nil, false
	}
	severity := "warning"
	score := 60
	kind := "dimension_growth"
	if previousBytes == 0 {
		kind = "new_dimension"
		score = 72
	} else {
		score = min(60+int(ratioValue*12), 95)
	}
	if ratioValue >= 2 || currentBytes >= previousBytes+50*1024*1024 {
		severity = "critical"
		score = max(score, 85)
	}
	dimension := stringValue(row["dimension"])
	key := stringValue(row["key"])
	summary := fmt.Sprintf("%s %s 近 %d 分钟流量较上一周期增长 %s", anomalyDimensionText(dimension), key, minutes, formatChangeRatioText(ratioValue))
	if previousBytes == 0 {
		summary = fmt.Sprintf("%s %s 近 %d 分钟新出现流量 %s", anomalyDimensionText(dimension), key, minutes, formatBytesText(currentBytes))
	}
	return map[string]any{
		"kind":             kind,
		"dimension":        dimension,
		"key":              key,
		"severity":         severity,
		"summary":          summary,
		"current_bytes":    currentBytes,
		"baseline_bytes":   previousBytes,
		"delta_bytes":      deltaBytes,
		"current_packets":  uintValue(row["current_packets"]),
		"baseline_packets": uintValue(row["previous_packets"]),
		"delta_packets":    int64Value(row["delta_packets"]),
		"change_ratio":     ratioValue,
		"score":            score,
	}, true
}

func anomalyDimensionText(dimension string) string {
	switch dimension {
	case "src_ip":
		return "源 IP"
	case "dst_ip":
		return "目的 IP"
	case "dst_port":
		return "目的端口"
	case "protocol":
		return "协议"
	case "service":
		return "应用服务"
	case "link":
		return "链路"
	default:
		return dimension
	}
}

func formatChangeRatioText(value float64) string {
	if value >= 999 {
		return "新增"
	}
	sign := "+"
	if value < 0 {
		sign = ""
	}
	return fmt.Sprintf("%s%.1f%%", sign, value*100)
}

func formatBytesText(value uint64) string {
	switch {
	case value >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(value)/float64(1024*1024*1024))
	case value >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(value)/float64(1024*1024))
	case value >= 1024:
		return fmt.Sprintf("%.2f KB", float64(value)/float64(1024))
	default:
		return fmt.Sprintf("%d B", value)
	}
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

func ensureAssetRiskRow(rows map[string]map[string]any, ip string) map[string]any {
	row := rows[ip]
	if row != nil {
		return row
	}
	row = map[string]any{
		"ip":                 ip,
		"name":               "",
		"owner":              "",
		"business":           "",
		"environment":        "未分类",
		"criticality":        "normal",
		"role":               "未知",
		"risk_score":         int64(0),
		"risk_level":         "low",
		"total_bytes":        uint64(0),
		"total_packets":      uint64(0),
		"external_bytes":     uint64(0),
		"external_peers":     int64(0),
		"external_sessions":  int64(0),
		"exposed_services":   int64(0),
		"high_risk_services": int64(0),
		"open_incidents":     int64(0),
		"critical_incidents": int64(0),
		"anomaly_count":      int64(0),
		"top_finding":        "",
		"top_finding_score":  int64(0),
		"recommended_action": "",
		"last_seen":          int64(0),
	}
	rows[ip] = row
	return row
}

func addAssetRiskScore(row map[string]any, score int64, finding string) {
	if score <= 0 {
		return
	}
	row["risk_score"] = int64Value(row["risk_score"]) + score
	if score >= int64Value(row["top_finding_score"]) && strings.TrimSpace(finding) != "" {
		row["top_finding_score"] = score
		row["top_finding"] = finding
	}
}

func criticalityRiskScore(criticality string) int64 {
	switch criticality {
	case "critical":
		return 18
	case "high":
		return 12
	case "low":
		return 2
	default:
		return 5
	}
}

func assetCriticalityLabel(criticality string) string {
	switch criticality {
	case "critical":
		return "核心"
	case "high":
		return "高"
	case "low":
		return "低"
	default:
		return "普通"
	}
}

func serviceExposureRiskScore(risk string) int64 {
	switch risk {
	case "critical":
		return 30
	case "high":
		return 22
	case "medium":
		return 14
	case "observe":
		return 10
	default:
		return 5
	}
}

func externalAccessRiskScore(risk, direction string) int64 {
	score := serviceExposureRiskScore(risk) / 2
	if strings.Contains(direction, "入站") {
		score += 12
	} else if strings.Contains(direction, "出站") {
		score += 7
	}
	return score
}

func incidentRiskScore(severity string, score int64) int64 {
	base := int64(12)
	if severity == "critical" {
		base = 28
	} else if severity == "warning" {
		base = 18
	}
	if score > 0 {
		return max(base, min(score/3, int64(35)))
	}
	return base
}

func anomalyRiskScore(severity string, score int64) int64 {
	base := int64(10)
	if severity == "critical" {
		base = 24
	} else if severity == "warning" {
		base = 15
	}
	if score > 0 {
		return max(base, min(score/4, int64(28)))
	}
	return base
}

func assetRiskLevel(score int64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "warning"
	default:
		return "low"
	}
}

func assetRiskAction(row map[string]any) string {
	if int64Value(row["critical_incidents"]) > 0 || stringValue(row["risk_level"]) == "critical" {
		return "优先核对公网暴露、高危服务和严重事件，确认负责人、访问来源和处置窗口"
	}
	if int64Value(row["high_risk_services"]) > 0 || int64Value(row["exposed_services"]) > 0 {
		return "检查服务暴露面、端口用途和访问策略，补齐资产负责人和业务标签"
	}
	if int64Value(row["anomaly_count"]) > 0 {
		return "复核异常波动来源，查看对象画像、关联会话和近期变更记录"
	}
	if stringValue(row["owner"]) == "" {
		return "补齐资产负责人、业务归属和环境标签，建立后续告警归属"
	}
	return "持续观察资产流量基线和事件变化"
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

func uint16Value(v any) uint16 {
	switch value := v.(type) {
	case uint16:
		return value
	case uint64:
		return uint16(value)
	case uint:
		return uint16(value)
	case int:
		return uint16(value)
	case int64:
		return uint16(value)
	case float64:
		return uint16(value)
	case string:
		n, _ := strconv.Atoi(value)
		return uint16(n)
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
