package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"nexaflow/internal/config"
)

func TestAuthTokenCarriesRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthSecret: "test-secret"})

	token, err := server.signAuthToken("alice", authRoleViewer, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	identity, ok := server.verifyAuthToken(token)
	if !ok {
		t.Fatal("expected token to verify")
	}
	if identity.Actor != "alice" {
		t.Fatalf("expected actor alice, got %q", identity.Actor)
	}
	if identity.Role != authRoleViewer {
		t.Fatalf("expected viewer role, got %q", identity.Role)
	}
}

func TestAuthTokenKeepsLegacyAdminRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthSecret: "test-secret"})

	payload := "legacy|" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	token := encoded + "." + server.authSignature(encoded)

	identity, ok := server.verifyAuthToken(token)
	if !ok {
		t.Fatal("expected legacy token to verify")
	}
	if identity.Actor != "legacy" {
		t.Fatalf("expected legacy actor, got %q", identity.Actor)
	}
	if identity.Role != authRoleAdmin {
		t.Fatalf("expected legacy admin role, got %q", identity.Role)
	}
}

func TestLoginRole(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthReadOnlyPassword: "viewer-pass"})
	if role := server.loginRole("admin-pass"); role != authRoleAdmin {
		t.Fatalf("expected admin role, got %q", role)
	}
	if role := server.loginRole("viewer-pass"); role != authRoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
	}
	if role := server.loginRole("bad-pass"); role != "" {
		t.Fatalf("expected empty role for invalid password, got %q", role)
	}
}

func TestRequestNeedsWriteAccess(t *testing.T) {
	getReq, _ := http.NewRequest(http.MethodGet, "/api/v1/collectors/config", nil)
	if requestNeedsWriteAccess(getReq) {
		t.Fatal("GET should not require write access")
	}

	postReq, _ := http.NewRequest(http.MethodPost, "/api/v1/collectors/config", nil)
	if !requestNeedsWriteAccess(postReq) {
		t.Fatal("POST should require write access")
	}

	healthReq, _ := http.NewRequest(http.MethodPost, "/healthz", nil)
	if requestNeedsWriteAccess(healthReq) {
		t.Fatal("non-api path should not require write access")
	}
}

func TestAuthRequiredBlocksViewerWrites(t *testing.T) {
	server := New(nil, config.Config{AuthPassword: "admin-pass", AuthReadOnlyPassword: "viewer-pass", AuthSecret: "test-secret"})
	viewerToken, err := server.signAuthToken("bob", authRoleViewer, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign viewer token: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	handler := server.authRequired(next)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	getReq.AddCookie(&http.Cookie{Name: authCookieName, Value: viewerToken})
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusAccepted {
		t.Fatalf("expected viewer GET to pass, got %d", getResp.Code)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/collectors/config", nil)
	postReq.AddCookie(&http.Cookie{Name: authCookieName, Value: viewerToken})
	postResp := httptest.NewRecorder()
	handler.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusForbidden {
		t.Fatalf("expected viewer POST to be forbidden, got %d", postResp.Code)
	}
}

func TestConfigDiffRows(t *testing.T) {
	before := map[string]any{
		"mode": "live_pcap",
		"alerts": map[string]any{
			"flow_share": 0.3,
			"silenced_subjects": []any{
				"dst_port:22",
			},
		},
	}
	after := map[string]any{
		"mode": "pcap_replay",
		"alerts": map[string]any{
			"flow_share": 0.4,
		},
		"session_topn": 1000,
	}

	changes := configDiffRows(before, after)
	byPath := map[string]map[string]string{}
	for _, change := range changes {
		byPath[change["path"]] = change
	}

	if byPath["mode"]["type"] != "changed" || byPath["mode"]["before"] != "live_pcap" || byPath["mode"]["after"] != "pcap_replay" {
		t.Fatalf("unexpected mode diff: %#v", byPath["mode"])
	}
	if byPath["alerts.flow_share"]["type"] != "changed" {
		t.Fatalf("expected flow share changed diff, got %#v", byPath["alerts.flow_share"])
	}
	if byPath["alerts.silenced_subjects[0]"]["type"] != "removed" {
		t.Fatalf("expected silence removal diff, got %#v", byPath["alerts.silenced_subjects[0]"])
	}
	if byPath["session_topn"]["type"] != "added" {
		t.Fatalf("expected session_topn added diff, got %#v", byPath["session_topn"])
	}
}

func TestCaptureDiagnosticReport(t *testing.T) {
	capture := map[string]any{
		"summary": map[string]any{
			"rx_dropped":     uint64(12),
			"tx_dropped":     uint64(0),
			"rx_errors":      uint64(0),
			"tx_errors":      uint64(0),
			"drop_ratio":     0.0004,
			"error_ratio":    0.0,
			"queue_pressure": 0.2,
		},
		"sources": []any{
			map[string]any{
				"packet_queue_pressure": 0.72,
				"window_queue_pressure": 0.91,
				"freshness_seconds":     int64(8),
			},
		},
	}
	quality := map[string]any{
		"summary": map[string]any{
			"freshness_seconds": int64(35),
			"coverage_ratio":    0.93,
		},
	}

	report := captureDiagnosticReport(capture, quality, 15)
	if status := stringValue(report["status"]); status != "critical" {
		t.Fatalf("expected critical status, got %q", status)
	}
	summary := mapValue(report["summary"])
	if int64Value(summary["critical_layers"]) != 2 {
		t.Fatalf("expected two critical layers, got %#v", summary)
	}
	if int64Value(summary["warning_layers"]) != 3 {
		t.Fatalf("expected three warning layers, got %#v", summary)
	}
	if len(sliceValue(report["layers"])) != 5 {
		t.Fatalf("expected five diagnostic layers, got %#v", report["layers"])
	}
	if len(sliceValue(report["recommendations"])) != 5 {
		t.Fatalf("expected recommendations for abnormal layers, got %#v", report["recommendations"])
	}
}
