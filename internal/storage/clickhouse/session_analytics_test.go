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
