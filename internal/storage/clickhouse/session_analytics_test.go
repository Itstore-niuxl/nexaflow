package clickhouse

import "testing"

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
