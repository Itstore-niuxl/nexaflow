package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func TestLoginIdentityUsesManagedUsers(t *testing.T) {
	runtimePath := t.TempDir() + "/runtime.json"
	passwordHash, err := hashPassword("analyst-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	settings := config.DefaultSystemSettings(config.Config{RuntimePath: runtimePath, AuthPassword: "legacy-admin"})
	settings.Security.AuthEnabled = true
	settings.Security.Users = []config.UserAccount{
		{Username: "alice", DisplayName: "Alice", Role: "analyst", Status: "active", PasswordHash: passwordHash},
		{Username: "disabled", DisplayName: "Disabled", Role: "admin", Status: "disabled", PasswordHash: passwordHash},
	}
	if err := config.SaveSystemSettings(config.SystemSettingsPath(runtimePath), settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	server := New(nil, config.Config{RuntimePath: runtimePath, AuthPassword: "legacy-admin"})
	identity, ok := server.loginIdentity("alice", "analyst-pass")
	if !ok {
		t.Fatal("expected managed user login")
	}
	if identity.Actor != "alice" || identity.Role != "analyst" {
		t.Fatalf("unexpected identity %#v", identity)
	}
	if _, ok := server.loginIdentity("disabled", "analyst-pass"); ok {
		t.Fatal("disabled user should not log in")
	}
	legacy, ok := server.loginIdentity("operator", "legacy-admin")
	if !ok || legacy.Role != authRoleAdmin {
		t.Fatalf("expected legacy admin fallback, got %#v ok=%v", legacy, ok)
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

func TestDiskUsageStatus(t *testing.T) {
	cases := []struct {
		ratio float64
		want  string
	}{
		{ratio: 0.1, want: "ok"},
		{ratio: 0.8, want: "warning"},
		{ratio: 0.89, want: "warning"},
		{ratio: 0.9, want: "critical"},
	}
	for _, tc := range cases {
		if got := diskUsageStatus(tc.ratio); got != tc.want {
			t.Fatalf("diskUsageStatus(%v) = %q, want %q", tc.ratio, got, tc.want)
		}
	}
}

func TestPlatformOpsStatusIncludesRetentionAndRecommendations(t *testing.T) {
	settings := config.DefaultSystemSettings(config.Config{})
	settings.Data.ClickHouseRetentionDays = 60
	settings.Data.SessionRetentionDays = 45
	status := platformOpsStatus(config.Config{RuntimePath: t.TempDir() + "/runtime.json"}, settings, "ok", "online")

	if stringValue(status["status"]) == "" {
		t.Fatalf("expected platform status, got %#v", status)
	}
	if stringValue(status["runtime_dir"]) == "" {
		t.Fatalf("expected runtime dir, got %#v", status)
	}
	if len(sliceValue(status["disks"])) == 0 {
		t.Fatalf("expected disk snapshots, got %#v", status["disks"])
	}
	if len(sliceValue(status["services"])) == 0 {
		t.Fatalf("expected service checks, got %#v", status["services"])
	}
	if len(mapValue(status["resources"])) == 0 {
		t.Fatalf("expected resource snapshot, got %#v", status["resources"])
	}
	if len(mapValue(status["deployment"])) == 0 {
		t.Fatalf("expected deployment snapshot, got %#v", status["deployment"])
	}
	retention := mapValue(status["data_retention"])
	if int64Value(retention["clickhouse_retention_days"]) != 60 {
		t.Fatalf("expected ClickHouse retention in status, got %#v", retention)
	}
	if len(sliceValue(status["recommendations"])) < 2 {
		t.Fatalf("expected retention recommendations, got %#v", status["recommendations"])
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

func TestBuildAICaptureDiagnosticsSummary(t *testing.T) {
	summary := buildAICaptureDiagnosticsSummary(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{
			"minutes": 15,
			"status":  "warning",
			"summary": map[string]any{
				"layer_count":     5,
				"critical_layers": 0,
				"warning_layers":  1,
			},
			"layers": []any{
				map[string]any{"name": "窗口覆盖率", "status": "warning", "metric": "覆盖率 94.0%", "detail": "存在短时窗口断档。"},
				map[string]any{"name": "数据新鲜度", "status": "healthy", "metric": "最新延迟 5 秒", "detail": "实时窗口正常。"},
			},
			"recommendations": []any{
				map[string]any{"level": "warning", "title": "窗口覆盖率", "detail": "检查采集器重启或 ClickHouse 写入失败时间点。"},
			},
		},
	)

	if stringValue(summary["kind"]) != "capture_diagnostics" {
		t.Fatalf("expected capture diagnostics kind, got %#v", summary["kind"])
	}
	if stringValue(summary["title"]) != "AI 采集诊断摘要" {
		t.Fatalf("unexpected title: %#v", summary["title"])
	}
	if len(sliceValue(summary["findings"])) < 3 {
		t.Fatalf("expected diagnostic findings, got %#v", summary["findings"])
	}
	if len(sliceValue(summary["actions"])) != 1 {
		t.Fatalf("expected recommendation action, got %#v", summary["actions"])
	}
	if float64Value(summary["confidence"]) <= 0 {
		t.Fatalf("expected confidence, got %#v", summary["confidence"])
	}
}

func TestEnhanceAISummaryUsesExternalModel(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected AI path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("missing auth header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"summary\":\"外部模型摘要\",\"findings\":[\"发现一\"],\"actions\":[\"处理一\"],\"evidence\":[\"证据一\"],\"confidence\":0.91}"}}]}`))
	}))
	defer gateway.Close()

	server := New(nil, config.Config{
		RuntimePath:      t.TempDir() + "/runtime.json",
		AIMode:           "openai",
		AIProvider:       "openai_compatible",
		AIModel:          "test-model",
		AIBaseURL:        gateway.URL,
		AIAPIKey:         "test-key",
		AIMaxContextRows: 12,
	})
	local := aiSummary(
		aiSummaryOptions{Enabled: true, Mode: "openai", Provider: "openai_compatible", Model: "test-model"},
		"report",
		"overview",
		"AI 巡检摘要",
		"本地摘要",
		0.5,
		[]string{"本地发现"},
		[]string{"本地证据"},
		[]string{"本地动作"},
	)
	enhanced, err := server.enhanceAISummary(context.Background(), local, map[string]any{"sample": "context"})
	if err != nil {
		t.Fatalf("enhance summary: %v", err)
	}
	if stringValue(enhanced["summary"]) != "外部模型摘要" {
		t.Fatalf("expected external summary, got %#v", enhanced)
	}
	if stringValue(enhanced["provider_status"]) != "external" {
		t.Fatalf("expected external provider status, got %#v", enhanced)
	}
	if !boolValue(enhanced["ai_generated"]) {
		t.Fatalf("expected ai_generated, got %#v", enhanced)
	}
	if len(sliceValue(enhanced["model_evidence"])) != 1 {
		t.Fatalf("expected model evidence, got %#v", enhanced)
	}
}

func TestAIApprovalRuleFlow(t *testing.T) {
	dir := t.TempDir()
	server := New(nil, config.Config{
		RuntimePath:   dir + "/collector_config.json",
		Mode:          "mock",
		Iface:         "eth0",
		CollectorID:   "test-collector",
		BandwidthMbps: 1000,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/approval-requests", nil)
	created, err := server.createAIApprovalRequest(req, aiApprovalRequest{
		Type:       "rule",
		Severity:   "warning",
		Title:      "AI 推荐：公网会话突增",
		Target:     "211.93.22.130 -> 10.2.0.12:8081",
		Summary:    "公网会话突增，建议沉淀检测规则。",
		Confidence: 0.82,
		Evidence:   []string{"会话数量：40"},
		Actions:    []string{"保存规则后观察误报。"},
		Payload: map[string]any{
			"proposed_rule": map[string]any{
				"name":               "AI 推荐：公网会话突增",
				"category":           "公网访问",
				"metric":             "external_sessions",
				"match":              "211.93.22.130 -> 10.2.0.12:8081",
				"operator":           "gte",
				"threshold":          float64(30),
				"severity":           "warning",
				"enabled":            true,
				"description":        "AI 审批测试规则",
				"recommended_action": "核对公网来源。",
			},
		},
	})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if created.Status != "pending" || created.ID == "" {
		t.Fatalf("unexpected created approval: %#v", created)
	}
	approved, err := server.reviewAIApprovalRequest(req, created.ID, "approve", "confirmed")
	if err != nil {
		t.Fatalf("approve request: %v", err)
	}
	if approved.Status != "approved" || approved.ApplyResult == "" {
		t.Fatalf("unexpected approved request: %#v", approved)
	}
	runtime := config.LoadRuntime(server.config.RuntimePath, config.DefaultRuntime(server.config))
	found := false
	for _, rule := range runtime.Alerts.DetectionRules {
		if rule.Name == "AI 推荐：公网会话突增" && rule.Metric == "external_sessions" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected approved rule in runtime, got %#v", runtime.Alerts.DetectionRules)
	}
	if _, err := server.reviewAIApprovalRequest(req, created.ID, "approve", "again"); err == nil {
		t.Fatal("expected duplicate approval to fail")
	}
}

func TestAIApprovalBulkReject(t *testing.T) {
	dir := t.TempDir()
	server := New(nil, config.Config{
		RuntimePath:   dir + "/collector_config.json",
		Mode:          "mock",
		Iface:         "eth0",
		CollectorID:   "test-collector",
		BandwidthMbps: 1000,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/approval-requests", nil)
	first, err := server.createAIApprovalRequest(req, aiApprovalRequest{
		Type:     "silence",
		Severity: "warning",
		Title:    "白名单复核 A",
		Target:   "dst_port:22",
		Summary:  "建议复核 SSH 白名单。",
		Payload:  map[string]any{"proposed_silence": map[string]any{"subject": "dst_port:22"}},
	})
	if err != nil {
		t.Fatalf("create first approval: %v", err)
	}
	second, err := server.createAIApprovalRequest(req, aiApprovalRequest{
		Type:     "asset_enrichment",
		Severity: "critical",
		Title:    "资产画像补全",
		Target:   "10.2.0.12",
		Summary:  "建议补全资产归属。",
		Payload:  map[string]any{"proposed_metadata": map[string]any{"ip": "10.2.0.12", "owner": "ops"}},
	})
	if err != nil {
		t.Fatalf("create second approval: %v", err)
	}
	result, err := server.bulkReviewAIApprovalRequests(req, []string{first.ID, second.ID, second.ID, "missing-id"}, "reject", "bulk cleanup")
	if err != nil {
		t.Fatalf("bulk reject: %v", err)
	}
	if result.Reviewed != 2 || result.Skipped != 1 {
		t.Fatalf("unexpected bulk result: %#v", result)
	}
	items, err := server.loadAIApprovalRequests()
	if err != nil {
		t.Fatalf("load approvals: %v", err)
	}
	rejected := 0
	for _, item := range items {
		if item.Status == "rejected" && item.ReviewNote == "bulk cleanup" {
			rejected++
		}
	}
	if rejected != 2 {
		t.Fatalf("expected two rejected approvals, got %#v", items)
	}
	if _, err := server.bulkReviewAIApprovalRequests(req, []string{first.ID}, "approve", "not allowed"); err == nil {
		t.Fatal("expected bulk approve to be rejected")
	}
}

func TestAIApprovalCreateDeduplicatesPendingRequest(t *testing.T) {
	dir := t.TempDir()
	server := New(nil, config.Config{
		RuntimePath:   dir + "/collector_config.json",
		Mode:          "mock",
		Iface:         "eth0",
		CollectorID:   "test-collector",
		BandwidthMbps: 1000,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/approval-requests", nil)
	request := aiApprovalRequest{
		Type:     "rule",
		Severity: "warning",
		Title:    "AI 推荐：公网会话突增",
		Target:   "211.93.22.130 -> 10.2.0.12:8081",
		Summary:  "公网会话突增，建议沉淀检测规则。",
		Payload:  map[string]any{"proposed_rule": map[string]any{"name": "AI 推荐：公网会话突增", "metric": "external_sessions", "threshold": float64(30)}},
	}
	first, err := server.createAIApprovalRequest(req, request)
	if err != nil {
		t.Fatalf("create first approval: %v", err)
	}
	request.Title = "  ai 推荐：公网会话突增  "
	duplicate, err := server.createAIApprovalRequest(req, request)
	if err != nil {
		t.Fatalf("create duplicate approval: %v", err)
	}
	if duplicate.ID != first.ID {
		t.Fatalf("expected duplicate to return existing approval, got first=%s duplicate=%s", first.ID, duplicate.ID)
	}
	items, err := server.loadAIApprovalRequests()
	if err != nil {
		t.Fatalf("load approvals: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one approval after duplicate submit, got %#v", items)
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
		[]map[string]any{
			{"id": "older-1", "subject": "10.2.0.12:8081", "kind": "external_session_burst", "category": "公网暴露", "severity": "critical", "status": "open", "summary": "公网会话突增复发", "last_seen": int64(1700000000), "score": int64(88)},
			{"id": "older-2", "subject": "211.93.22.130 -> 10.2.0.12", "kind": "external_session_burst", "category": "公网暴露", "severity": "warning", "status": "ack", "summary": "同类公网会话突增", "last_seen": int64(1699999000), "score": int64(80)},
		},
		[]string{"历史相似事件查询部分降级"},
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
	if len(sliceValue(investigation["similar_incidents"])) != 2 {
		t.Fatalf("expected similar incidents, got %#v", investigation["similar_incidents"])
	}
	if len(sliceValue(investigation["evidence_items"])) == 0 {
		t.Fatalf("expected structured evidence items, got %#v", investigation["evidence_items"])
	}
	contextQuality := mapValue(investigation["context_quality"])
	if int64Value(contextQuality["score"]) <= 0 {
		t.Fatalf("expected context quality score, got %#v", contextQuality)
	}
	if len(sliceValue(investigation["degraded_reasons"])) != 1 {
		t.Fatalf("expected degraded reasons, got %#v", investigation["degraded_reasons"])
	}
	recurrence := mapValue(investigation["recurrence"])
	if !boolValue(recurrence["recurring"]) {
		t.Fatalf("expected recurrence marker, got %#v", recurrence)
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

func TestBuildAIIncidentActionSuggestions(t *testing.T) {
	contextData := map[string]any{
		"subject": "211.93.22.130 -> 10.2.0.12:8081",
		"kind":    "external_session_burst",
		"selector": map[string]any{
			"src_ip":   "211.93.22.130",
			"dst_ip":   "10.2.0.12",
			"dst_port": "8081",
		},
		"sessions": []any{
			map[string]any{"src_ip": "211.93.22.130", "dst_ip": "10.2.0.12", "dst_port": "8081", "protocol": "tcp", "service": "HTTP Alternate", "risk": "medium", "bytes": uint64(7340032), "packets": uint64(6800)},
		},
		"insights": []any{map[string]any{"severity": "warning", "summary": "公网会话突增"}},
	}
	investigation := buildAIIncidentInvestigation(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{"subject": "211.93.22.130 -> 10.2.0.12:8081", "kind": "external_session_burst", "severity": "warning", "bytes": uint64(7340032), "packets": uint64(6800)},
		contextData,
		nil,
		nil,
		nil,
	)
	result := buildAIIncidentActionSuggestions(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		map[string]any{"subject": "211.93.22.130 -> 10.2.0.12:8081", "kind": "external_session_burst", "severity": "warning", "bytes": uint64(7340032), "packets": uint64(6800)},
		contextData,
		investigation,
		15,
		8,
	)
	suggestions := sliceValue(result["suggestions"])
	if len(suggestions) < 2 {
		t.Fatalf("expected incident action suggestions, got %#v", result)
	}
	hasRule := false
	hasSilence := false
	for _, item := range suggestions {
		row := mapValue(item)
		if mapValue(row["proposed_rule"])["metric"] != "" {
			hasRule = true
		}
		if mapValue(row["proposed_silence"])["subject"] != "" {
			hasSilence = true
		}
	}
	if !hasRule || !hasSilence {
		t.Fatalf("expected rule and silence proposals, got %#v", suggestions)
	}
}

func TestReportOverviewCSV(t *testing.T) {
	body, err := reportOverviewCSV(map[string]any{
		"summary": map[string]any{
			"bytes":              uint64(7340032),
			"packets":            uint64(6800),
			"asset_count":        int64(3),
			"critical_assets":    int64(1),
			"open_incidents":     int64(2),
			"anomaly_count":      int64(1),
			"exposed_services":   int64(2),
			"external_access":    int64(1),
			"avg_mbps":           8.4,
			"peak_mbps":          42.1,
			"p95_mbps":           21.3,
			"utilization":        0.12,
			"critical_incidents": int64(1),
		},
		"recommendations": []map[string]any{
			{"level": "critical", "title": "处理公网暴露", "detail": "核对端口暴露策略"},
		},
		"incidents": []map[string]any{
			{"subject": "211.93.22.130 -> 10.2.0.12:8081", "severity": "critical", "status": "open", "source": "rule", "kind": "external_session_burst", "score": int64(90), "bytes": uint64(7340032), "packets": uint64(6800), "summary": "公网会话突增", "recommended_action": "核对公网来源"},
		},
		"top_src": []map[string]any{
			{"key": "211.93.22.130", "bytes": uint64(7340032), "packets": uint64(6800)},
		},
	})
	if err != nil {
		t.Fatalf("build csv: %v", err)
	}
	text := string(body)
	for _, want := range []string{"section,object,level_status", "summary,overview", "recommendation", "incident", "top_src"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected CSV to contain %q, got %s", want, text)
		}
	}
}

func TestAuditEventsCSV(t *testing.T) {
	body, err := auditEventsCSV([]map[string]any{
		{"ts": int64(1700000000), "actor": "admin", "action": "report.export", "target": "overview", "summary": "导出巡检报表", "client_ip": "127.0.0.1", "detail_text": `{"format":"csv"}`},
	})
	if err != nil {
		t.Fatalf("build audit csv: %v", err)
	}
	text := string(body)
	for _, want := range []string{"time,actor,action,target,summary,client_ip,detail", "admin", "report.export", "导出巡检报表"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected audit CSV to contain %q, got %s", want, text)
		}
	}
}

func TestConfigVersionsCSV(t *testing.T) {
	body, err := configVersionsCSV([]map[string]any{
		{"ts": int64(1700000000), "id": "cfg-1", "actor": "admin", "scope": "system", "target": "settings", "action": "system.settings.update", "summary": "更新系统设置", "client_ip": "127.0.0.1", "config_text": `{"ai":{"mode":"local_mock"}}`},
	})
	if err != nil {
		t.Fatalf("build config csv: %v", err)
	}
	text := string(body)
	for _, want := range []string{"time,id,actor,scope,target,action,summary,client_ip,config", "cfg-1", "system.settings.update", `""mode"":""local_mock""`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected config CSV to contain %q, got %s", want, text)
		}
	}
}

func TestAIApprovalRequestsCSV(t *testing.T) {
	body, err := aiApprovalRequestsCSV([]aiApprovalRequest{
		{
			ID:          "ai-approval-1",
			Type:        "rule",
			Status:      "approved",
			Severity:    "warning",
			Title:       "AI 推荐：公网会话突增",
			Target:      "211.93.22.130 -> 10.2.0.12:8081",
			Summary:     "建议沉淀检测规则。",
			Confidence:  0.82,
			Evidence:    []string{"会话数量：40"},
			Actions:     []string{"保存规则后观察误报。"},
			Payload:     map[string]any{"proposed_rule": map[string]any{"name": "公网会话突增"}},
			CreatedBy:   "admin",
			CreatedAt:   1700000000,
			ReviewedBy:  "admin",
			ReviewedAt:  1700000100,
			ReviewNote:  "确认执行",
			AppliedAt:   1700000200,
			ApplyResult: "saved rule rule-1",
		},
	})
	if err != nil {
		t.Fatalf("build ai approval csv: %v", err)
	}
	text := string(body)
	for _, want := range []string{"created_time,id,type,status,severity,title,target,summary,confidence", "ai-approval-1", "AI 推荐：公网会话突增", "saved rule rule-1", `""name"":""公网会话突增""`} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected AI approval CSV to contain %q, got %s", want, text)
		}
	}
}

func TestBuildAIApprovalStats(t *testing.T) {
	now := int64(1700100000)
	stats := buildAIApprovalStats([]aiApprovalRequest{
		{
			ID:        "pending-critical",
			Type:      "rule",
			Status:    "pending",
			Severity:  "critical",
			CreatedAt: now - 26*60*60,
		},
		{
			ID:        "pending-warning",
			Type:      "silence",
			Status:    "pending",
			Severity:  "warning",
			CreatedAt: now - 30*60,
		},
		{
			ID:         "approved-rule",
			Type:       "rule",
			Status:     "approved",
			Severity:   "warning",
			CreatedAt:  now - 10*60,
			ReviewedAt: now - 4*60,
		},
		{
			ID:         "rejected-asset",
			Type:       "asset_enrichment",
			Status:     "rejected",
			Severity:   "info",
			CreatedAt:  now - 20*60,
			ReviewedAt: now - 8*60,
		},
	}, now)
	if int64Value(stats["pending"]) != 2 {
		t.Fatalf("expected 2 pending approvals, got %#v", stats)
	}
	if int64Value(stats["critical_pending"]) != 1 {
		t.Fatalf("expected 1 critical pending approval, got %#v", stats)
	}
	if int64Value(stats["overdue_pending"]) != 1 {
		t.Fatalf("expected 1 overdue pending approval, got %#v", stats)
	}
	if int64Value(stats["average_review_seconds"]) != 540 {
		t.Fatalf("expected 540s average review time, got %#v", stats)
	}
	if !boolValue(stats["requires_operator_attention"]) {
		t.Fatalf("expected operator attention, got %#v", stats)
	}
	if len(stats["pending_type_counts"].([]aiApprovalCount)) != 2 {
		t.Fatalf("expected pending type distribution, got %#v", stats)
	}
}

func TestFilterAIApprovalRequests(t *testing.T) {
	items := []aiApprovalRequest{
		{ID: "rule-critical", Type: "rule", Status: "pending", Severity: "critical"},
		{ID: "rule-warning", Type: "rule", Status: "approved", Severity: "warning"},
		{ID: "asset-critical", Type: "asset_enrichment", Status: "pending", Severity: "critical"},
	}
	filtered := filterAIApprovalRequests(items, aiApprovalFilters{Status: "pending", Type: "rule", Severity: "critical"})
	if len(filtered) != 1 || filtered[0].ID != "rule-critical" {
		t.Fatalf("expected critical pending rule only, got %#v", filtered)
	}
	filtered = filterAIApprovalRequests(items, aiApprovalFilters{Severity: "critical"})
	if len(filtered) != 2 {
		t.Fatalf("expected two critical approvals, got %#v", filtered)
	}
	if normalizeApprovalFilterValue("all") != "" || normalizeApprovalFilterValue(" pending ") != "pending" {
		t.Fatal("unexpected filter normalization")
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

func TestBuildAIAssetEnrichmentSuggestions(t *testing.T) {
	risks := []map[string]any{
		{
			"ip":                 "10.2.0.12",
			"name":               "",
			"owner":              "",
			"business":           "",
			"environment":        "未分类",
			"criticality":        "normal",
			"role":               "server",
			"risk_score":         int64(86),
			"risk_level":         "critical",
			"external_peers":     int64(2),
			"external_sessions":  int64(40),
			"exposed_services":   int64(3),
			"open_incidents":     int64(2),
			"critical_incidents": int64(1),
			"top_finding":        "公网暴露",
		},
	}
	result := buildAIAssetEnrichmentSuggestions(
		aiSummaryOptions{Enabled: true, Mode: "local_mock", Provider: "local_mock", Model: "nexaflow-local-summary"},
		risks,
		15,
		8,
	)
	suggestions := sliceValue(result["suggestions"])
	if len(suggestions) != 1 {
		t.Fatalf("expected one asset suggestion, got %#v", result)
	}
	suggestion := mapValue(suggestions[0])
	if len(sliceValue(suggestion["missing_fields"])) < 4 {
		t.Fatalf("expected missing fields, got %#v", suggestion)
	}
	metadata := mapValue(suggestion["proposed_metadata"])
	if stringValue(metadata["ip"]) != "10.2.0.12" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	if stringValue(metadata["criticality"]) != "critical" {
		t.Fatalf("expected critical metadata, got %#v", metadata)
	}
	tags := sliceValue(metadata["tags"])
	if len(tags) == 0 {
		t.Fatalf("expected inferred tags, got %#v", metadata)
	}
}
