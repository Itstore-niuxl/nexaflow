package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"nexaflow/internal/config"
	"nexaflow/internal/model"
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

	aiQueryReq, _ := http.NewRequest(http.MethodPost, "/api/v1/ai/query", nil)
	if requestNeedsWriteAccess(aiQueryReq) {
		t.Fatal("AI query is read-only and should not require write access")
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

func TestBuildAIIncidentSummary(t *testing.T) {
	summary := buildAIIncidentSummary(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{"subject": "10.2.0.12:8081", "kind": "external_session_burst", "severity": "critical", "bytes": uint64(10485760)},
		map[string]any{
			"subject": "10.2.0.12:8081",
			"sessions": []any{
				map[string]any{"key": "211.93.22.130 -> 10.2.0.12 / 8081/TCP", "bytes": uint64(7340032), "packets": uint64(6800)},
			},
			"insights": []any{
				map[string]any{"severity": "critical", "summary": "公网会话突增"},
			},
			"anomalies": []any{
				map[string]any{"summary": "新增公网访问流量"},
			},
			"relations": map[string]any{
				"summary": map[string]any{"bytes": uint64(10485760)},
			},
		},
	)

	if !boolValue(summary["enabled"]) {
		t.Fatal("expected AI summary to be enabled")
	}
	if stringValue(summary["kind"]) != "incident" {
		t.Fatalf("expected incident summary, got %#v", summary)
	}
	if len(sliceValue(summary["findings"])) < 3 {
		t.Fatalf("expected findings with context, got %#v", summary["findings"])
	}
	if float64Value(summary["confidence"]) <= 0 {
		t.Fatalf("expected positive confidence, got %#v", summary["confidence"])
	}
}

func TestBuildAIReportSummaryDisabled(t *testing.T) {
	summary := buildAIReportSummary(
		aiSummaryOptions{Enabled: false, Mode: "disabled", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{
			"summary": map[string]any{"minutes": 15, "bytes": uint64(1024)},
		},
	)

	if boolValue(summary["enabled"]) {
		t.Fatal("expected disabled AI summary")
	}
	if stringValue(summary["title"]) != "AI 摘要已关闭" {
		t.Fatalf("expected disabled title, got %#v", summary["title"])
	}
	if len(sliceValue(summary["actions"])) == 0 {
		t.Fatalf("expected disabled mode action, got %#v", summary["actions"])
	}
}

func TestAIIncidentContextUsable(t *testing.T) {
	if aiIncidentContextUsable(map[string]any{}) {
		t.Fatal("empty context should not be usable")
	}
	if !aiIncidentContextUsable(map[string]any{
		"dst_ip_profile": map[string]any{"ip": "10.2.0.12"},
	}) {
		t.Fatal("asset profile context should be usable")
	}
	if !aiIncidentContextUsable(map[string]any{
		"sessions": []any{map[string]any{"key": "flow"}},
	}) {
		t.Fatal("session context should be usable")
	}
}

func TestParseAIQueryIntent(t *testing.T) {
	cases := []struct {
		question string
		id       string
		minutes  int
	}{
		{"最近 30 分钟哪个公网 IP 访问最多？", "external_access", 30},
		{"10.2.0.12 最近连接了哪些外部地址？", "sessions_for_ip", 15},
		{"有没有新增的高风险端口暴露？", "external_access", 15},
		{"最近 1 小时异常增长最大的服务是什么？", "anomalies", 60},
	}
	for _, tt := range cases {
		minutes := aiQueryMinutes(tt.question, 15)
		intent := parseAIQueryIntent(tt.question, minutes, 8)
		if intent.ID != tt.id {
			t.Fatalf("expected %s for %q, got %s", tt.id, tt.question, intent.ID)
		}
		if intent.Minutes != tt.minutes {
			t.Fatalf("expected %d minutes for %q, got %d", tt.minutes, tt.question, intent.Minutes)
		}
		if intent.API == "" || intent.Description == "" {
			t.Fatalf("expected API and description for %#v", intent)
		}
	}
}

func TestBuildAIQueryResponse(t *testing.T) {
	intent := parseAIQueryIntent("最近 30 分钟哪个公网 IP 访问最多？", 30, 8)
	response := buildAIQueryResponse(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		intent,
		[]map[string]any{
			{"public_ip": "211.93.22.130", "internal_ip": "10.2.0.12", "bytes": uint64(7340032), "packets": uint64(6800), "risk": "high"},
		},
	)
	if stringValue(response["question"]) == "" {
		t.Fatal("expected original question")
	}
	if len(sliceValue(response["findings"])) < 2 {
		t.Fatalf("expected findings, got %#v", response["findings"])
	}
	if len(sliceValue(response["rows"])) != 1 {
		t.Fatalf("expected one result row, got %#v", response["rows"])
	}
	if float64Value(response["confidence"]) <= 0 {
		t.Fatalf("expected confidence, got %#v", response["confidence"])
	}
}

func TestBuildAIIncidentInvestigation(t *testing.T) {
	investigation := buildAIIncidentInvestigation(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{"subject": "10.2.0.12:8081", "kind": "external_session_burst", "severity": "critical"},
		map[string]any{
			"subject": "10.2.0.12:8081",
			"sessions": []any{
				map[string]any{"key": "211.93.22.130 -> 10.2.0.12 / 8081/TCP", "bytes": uint64(7340032)},
			},
			"insights": []any{
				map[string]any{"severity": "critical", "summary": "公网会话突增"},
			},
			"anomalies": []any{
				map[string]any{"summary": "新增公网访问流量"},
			},
		},
		nil,
	)
	if stringValue(investigation["subject"]) != "10.2.0.12:8081" {
		t.Fatalf("unexpected subject: %#v", investigation["subject"])
	}
	if len(sliceValue(investigation["root_causes"])) < 4 {
		t.Fatalf("expected root cause candidates, got %#v", investigation["root_causes"])
	}
	if len(sliceValue(investigation["evidence_chain"])) == 0 {
		t.Fatalf("expected evidence chain, got %#v", investigation["evidence_chain"])
	}
}

func TestBuildAIGovernanceSuggestions(t *testing.T) {
	report := map[string]any{
		"incidents": []map[string]any{
			{"subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "critical", "summary": "公网会话突增", "bytes": uint64(7340032), "packets": uint64(6800), "recommended_action": "核对公网来源"},
		},
		"external_access": []map[string]any{
			{"public_ip": "211.93.22.130", "internal_ip": "10.2.0.12", "port": "8081", "service": "HTTP Alternate", "risk": "medium", "session_count": int64(40), "bytes": uint64(7340032), "packets": uint64(6800)},
		},
		"exposures": []map[string]any{
			{"ip": "10.2.0.12", "port": "8081", "service": "HTTP Alternate", "risk": "high", "client_count": int64(6), "bytes": uint64(7340032), "packets": uint64(6800)},
		},
		"anomalies": []map[string]any{
			{"dimension": "service", "key": "SSH", "severity": "warning", "summary": "SSH 新增流量", "current_bytes": uint64(18874368), "change_ratio": 9.9},
		},
		"asset_risks": []map[string]any{
			{"ip": "10.2.0.12", "risk_level": "critical", "risk_score": int64(86), "open_incidents": int64(2), "exposed_services": int64(3), "external_peers": int64(2), "top_finding": "公网暴露"},
		},
	}

	result := buildAIGovernanceSuggestions(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		report,
		config.Alerts{},
		15,
		8,
	)
	suggestions := sliceValue(result["suggestions"])
	if len(suggestions) < 4 {
		t.Fatalf("expected governance suggestions, got %#v", result)
	}
	first := mapValue(suggestions[0])
	if mapValue(first["proposed_rule"])["metric"] == "" {
		t.Fatalf("expected proposed rule in first suggestion, got %#v", first)
	}
	hasSilence := false
	hasAsset := false
	for _, item := range suggestions {
		row := mapValue(item)
		if mapValue(row["proposed_silence"])["subject"] != "" {
			hasSilence = true
		}
		if stringValue(row["type"]) == "asset_governance" {
			hasAsset = true
		}
	}
	if !hasSilence {
		t.Fatalf("expected whitelist review suggestion, got %#v", suggestions)
	}
	if !hasAsset {
		t.Fatalf("expected asset governance suggestion, got %#v", suggestions)
	}
}

func TestBuildAIRuleEffectiveness(t *testing.T) {
	rules := []model.DetectionRule{
		{ID: "rule-noisy", Name: "公网会话突增", Category: "公网访问", Metric: "external_sessions", Operator: "gte", Threshold: 20, Severity: "warning", Enabled: true},
		{ID: "rule-quiet", Name: "SSH 新增流量", Category: "行为基线", Metric: "service_bytes", Operator: "gte", Threshold: 1024, Severity: "critical", Enabled: true},
		{ID: "rule-disabled", Name: "旧规则", Category: "历史", Metric: "flow_bytes", Operator: "gte", Threshold: 1024, Severity: "warning", Enabled: false},
	}
	findings := []map[string]any{
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(40), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(41), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(42), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(43), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(44), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(45), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(46), "bytes": uint64(7340032), "packets": uint64(6800)},
		{"rule_id": "rule-noisy", "rule_name": "公网会话突增", "subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "warning", "value": float64(47), "bytes": uint64(7340032), "packets": uint64(6800)},
	}

	result := buildAIRuleEffectiveness(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		rules,
		findings,
		config.Alerts{SilencedSubjects: []string{"211.93.22.130 -> 10.2.0.12:8081"}},
		15,
	)
	summary := mapValue(result["summary"])
	if int64Value(summary["rule_count"]) != 3 {
		t.Fatalf("expected three rules, got %#v", summary)
	}
	if int64Value(summary["noisy_rules"]) != 1 {
		t.Fatalf("expected one noisy rule, got %#v", summary)
	}
	rows := sliceValue(result["rules"])
	if len(rows) != 3 {
		t.Fatalf("expected rule rows, got %#v", rows)
	}
	var noisy map[string]any
	for _, item := range rows {
		row := mapValue(item)
		if stringValue(row["id"]) == "rule-noisy" {
			noisy = row
			break
		}
	}
	if noisy == nil {
		t.Fatalf("expected noisy rule row, got %#v", rows)
	}
	if stringValue(noisy["noise_level"]) != "noisy" {
		t.Fatalf("expected noisy rule, got %#v", noisy)
	}
	if int64Value(noisy["silenced_hits"]) == 0 {
		t.Fatalf("expected silenced hits, got %#v", noisy)
	}
	if len(sliceValue(result["tuning_suggestions"])) == 0 {
		t.Fatalf("expected tuning suggestions, got %#v", result)
	}
}
