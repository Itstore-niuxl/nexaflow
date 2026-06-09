package clickhouse

import (
	"testing"

	"nexaflow/internal/model"
)

func TestServiceAnalyticsFromSessions(t *testing.T) {
	sessions := []map[string]any{
		{
			"key":        "10.0.0.10:50100 -> 172.16.0.20:443 / tcp",
			"bytes":      uint64(1000),
			"packets":    uint64(10),
			"first_seen": int64(100),
			"last_seen":  int64(105),
		},
		{
			"key":        "10.0.0.11:50101 -> 172.16.0.20:443 / tcp",
			"bytes":      uint64(2000),
			"packets":    uint64(20),
			"first_seen": int64(101),
			"last_seen":  int64(106),
		},
		{
			"key":        "10.0.0.12:50102 -> 172.16.0.30:22 / tcp",
			"bytes":      uint64(3000),
			"packets":    uint64(30),
			"first_seen": int64(102),
			"last_seen":  int64(107),
		},
	}

	ports, details := serviceAnalyticsFromSessions(sessions, 10)
	if len(ports) != 2 {
		t.Fatalf("expected 2 service ports, got %d", len(ports))
	}
	if len(details) != 2 {
		t.Fatalf("expected 2 service details, got %d", len(details))
	}

	var https map[string]any
	for _, row := range details {
		if stringValue(row["service"]) == "HTTPS" {
			https = row
		}
	}
	if https == nil {
		t.Fatal("expected HTTPS service detail")
	}
	if uintValue(https["bytes"]) != 3000 {
		t.Fatalf("expected HTTPS bytes 3000, got %d", uintValue(https["bytes"]))
	}
	if uintValue(https["client_count"]) != 2 {
		t.Fatalf("expected HTTPS client count 2, got %d", uintValue(https["client_count"]))
	}
	if uintValue(https["server_count"]) != 1 {
		t.Fatalf("expected HTTPS server count 1, got %d", uintValue(https["server_count"]))
	}
}

func TestSessionRowAddsAnalysisFields(t *testing.T) {
	row := sessionRow(
		model.TopItem{Key: "211.93.22.130:52000 -> 10.2.0.12:22 / tcp", Bytes: 150 * 1024 * 1024, Packets: 120000},
		100,
		120,
	)
	if stringValue(row["analysis_level"]) != "critical" {
		t.Fatalf("expected critical analysis level, got %#v", row)
	}
	if int64Value(row["analysis_score"]) < 80 {
		t.Fatalf("expected high analysis score, got %#v", row["analysis_score"])
	}
	flags, ok := row["analysis_flags"].([]string)
	if !ok || len(flags) < 3 {
		t.Fatalf("expected analysis flags, got %#v", row["analysis_flags"])
	}
	if stringValue(row["recommendation"]) == "" {
		t.Fatalf("expected recommendation, got %#v", row)
	}
}

func TestCaptureQualityRowStatus(t *testing.T) {
	healthy := map[string]any{
		"rx_packets":        uint64(1000),
		"tx_packets":        uint64(1000),
		"rx_dropped":        uint64(0),
		"tx_dropped":        uint64(0),
		"rx_errors":         uint64(0),
		"tx_errors":         uint64(0),
		"drop_ratio":        0.0,
		"error_ratio":       0.0,
		"queue_pressure":    0.0,
		"freshness_seconds": int64(5),
	}
	if status := captureQualityRowStatus(healthy); status != "healthy" {
		t.Fatalf("expected healthy, got %s", status)
	}

	dropped := map[string]any{
		"rx_packets":        uint64(1000),
		"tx_packets":        uint64(1000),
		"rx_dropped":        uint64(1),
		"tx_dropped":        uint64(0),
		"rx_errors":         uint64(0),
		"tx_errors":         uint64(0),
		"drop_ratio":        0.0005,
		"error_ratio":       0.0,
		"queue_pressure":    0.0,
		"freshness_seconds": int64(5),
	}
	if status := captureQualityRowStatus(dropped); status != "warning" {
		t.Fatalf("expected warning, got %s", status)
	}

	errors := map[string]any{
		"rx_packets":        uint64(1000),
		"tx_packets":        uint64(1000),
		"rx_dropped":        uint64(0),
		"tx_dropped":        uint64(0),
		"rx_errors":         uint64(1),
		"tx_errors":         uint64(0),
		"drop_ratio":        0.0,
		"error_ratio":       0.0005,
		"queue_pressure":    0.0,
		"freshness_seconds": int64(5),
	}
	if status := captureQualityRowStatus(errors); status != "critical" {
		t.Fatalf("expected critical, got %s", status)
	}

	queue := map[string]any{
		"rx_packets":        uint64(1000),
		"tx_packets":        uint64(1000),
		"rx_dropped":        uint64(0),
		"tx_dropped":        uint64(0),
		"rx_errors":         uint64(0),
		"tx_errors":         uint64(0),
		"drop_ratio":        0.0,
		"error_ratio":       0.0,
		"queue_pressure":    0.95,
		"freshness_seconds": int64(5),
	}
	if status := captureQualityRowStatus(queue); status != "critical" {
		t.Fatalf("expected critical queue pressure, got %s", status)
	}
}

func TestAnnotateCaptureQualityRow(t *testing.T) {
	row := map[string]any{
		"rx_packets":        uint64(100000),
		"tx_packets":        uint64(100000),
		"rx_dropped":        uint64(12),
		"tx_dropped":        uint64(0),
		"rx_errors":         uint64(1),
		"tx_errors":         uint64(0),
		"drop_ratio":        0.002,
		"error_ratio":       0.0015,
		"queue_pressure":    0.92,
		"freshness_seconds": int64(18),
	}
	annotateCaptureQualityRow(row)
	if int64Value(row["health_score"]) >= 50 {
		t.Fatalf("expected low health score, got %#v", row["health_score"])
	}
	if stringValue(row["diagnosis"]) == "" {
		t.Fatalf("expected diagnosis, got %#v", row)
	}
	if stringValue(row["recommendation"]) == "" {
		t.Fatalf("expected recommendation, got %#v", row)
	}
}

func TestCaptureQualityTimelineStatusAndEvents(t *testing.T) {
	timeline := []map[string]any{
		{
			"ts":              int64(100),
			"drops":           uint64(0),
			"errors":          uint64(0),
			"queue_pressure":  0.10,
			"bytes":           uint64(1000),
			"packets":         uint64(100),
			"source_count":    uint64(1),
			"interface_count": uint64(1),
		},
		{
			"ts":              int64(105),
			"drops":           uint64(2),
			"errors":          uint64(0),
			"queue_pressure":  0.20,
			"bytes":           uint64(2000),
			"packets":         uint64(200),
			"source_count":    uint64(1),
			"interface_count": uint64(1),
		},
		{
			"ts":              int64(110),
			"drops":           uint64(0),
			"errors":          uint64(0),
			"queue_pressure":  0.95,
			"bytes":           uint64(3000),
			"packets":         uint64(300),
			"source_count":    uint64(2),
			"interface_count": uint64(2),
		},
	}
	for _, row := range timeline {
		row["status"] = captureQualityTimelineStatus(row)
		row["summary"] = captureQualityTimelineSummary(row)
	}
	if status := stringValue(timeline[0]["status"]); status != "healthy" {
		t.Fatalf("expected healthy timeline point, got %s", status)
	}
	if status := stringValue(timeline[1]["status"]); status != "warning" {
		t.Fatalf("expected warning timeline point, got %s", status)
	}
	if status := stringValue(timeline[2]["status"]); status != "critical" {
		t.Fatalf("expected critical timeline point, got %s", status)
	}
	events := captureQualityEvents(timeline, 10)
	if len(events) != 2 {
		t.Fatalf("expected two abnormal events, got %#v", events)
	}
	if int64Value(events[0]["ts"]) != 110 {
		t.Fatalf("expected newest event first, got %#v", events[0])
	}
	if stringValue(events[0]["status"]) != "critical" {
		t.Fatalf("expected critical newest event, got %#v", events[0])
	}
	if stringValue(events[1]["status"]) != "warning" {
		t.Fatalf("expected warning second event, got %#v", events[1])
	}
}

func TestIncidentContextSelectorParsesEndpointPort(t *testing.T) {
	selector := incidentContextSelector("169.254.0.4 -> 10.2.0.12:80", "custom_rule")

	if selector["dimension"] != "pair" {
		t.Fatalf("expected pair dimension, got %#v", selector)
	}
	if selector["key"] != "169.254.0.4 -> 10.2.0.12" {
		t.Fatalf("expected normalized pair key, got %#v", selector)
	}
	if selector["query"] != "10.2.0.12" {
		t.Fatalf("expected dst ip query, got %#v", selector)
	}
	if selector["src_ip"] != "169.254.0.4" || selector["dst_ip"] != "10.2.0.12" || selector["dst_port"] != "80" {
		t.Fatalf("expected parsed endpoint fields, got %#v", selector)
	}
}
