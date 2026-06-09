package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nexaflow/internal/config"
	"nexaflow/internal/model"
	"nexaflow/internal/storage/clickhouse"
)

const authCookieName = "nexaflow_session"

type contextKey string

const actorContextKey contextKey = "actor"
const roleContextKey contextKey = "role"

const (
	authRoleAdmin  = "admin"
	authRoleViewer = "viewer"
)

type authIdentity struct {
	Actor string
	Role  string
}

type Server struct {
	store  *clickhouse.Store
	config config.Config
}

func New(store *clickhouse.Store, cfg config.Config) *Server {
	return &Server{store: store, config: cfg}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.health)
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/api/v1/auth/status", s.authStatus)
	mux.HandleFunc("/api/v1/auth/login", s.authLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.authLogout)
	mux.HandleFunc("/api/v1/dashboard/summary", s.summary)
	mux.HandleFunc("/api/v1/traffic/topn", s.topn)
	mux.HandleFunc("/api/v1/traffic/timeseries", s.timeseries)
	mux.HandleFunc("/api/v1/traffic/ip-profile", s.ipProfile)
	mux.HandleFunc("/api/v1/traffic/port-profile", s.portProfile)
	mux.HandleFunc("/api/v1/traffic/windows", s.windows)
	mux.HandleFunc("/api/v1/traffic/matrix", s.matrix)
	mux.HandleFunc("/api/v1/traffic/service-map", s.serviceMap)
	mux.HandleFunc("/api/v1/traffic/service-analytics", s.serviceAnalytics)
	mux.HandleFunc("/api/v1/traffic/service-exposure", s.serviceExposure)
	mux.HandleFunc("/api/v1/traffic/external-access", s.externalAccess)
	mux.HandleFunc("/api/v1/traffic/protocol-timeseries", s.protocolTimeseries)
	mux.HandleFunc("/api/v1/traffic/port-timeseries", s.portTimeseries)
	mux.HandleFunc("/api/v1/traffic/direction-timeseries", s.directionTimeseries)
	mux.HandleFunc("/api/v1/traffic/dimension-timeseries", s.dimensionTimeseries)
	mux.HandleFunc("/api/v1/traffic/object-relations", s.objectRelations)
	mux.HandleFunc("/api/v1/traffic/sessions", s.sessions)
	mux.HandleFunc("/api/v1/traffic/search", s.search)
	mux.HandleFunc("/api/v1/traffic/analysis", s.trafficAnalysis)
	mux.HandleFunc("/api/v1/traffic/baseline-profile", s.trafficBaselineProfile)
	mux.HandleFunc("/api/v1/traffic/capacity", s.capacityPlanning)
	mux.HandleFunc("/api/v1/traffic/changes", s.trafficChanges)
	mux.HandleFunc("/api/v1/traffic/anomalies", s.trafficAnomalies)
	mux.HandleFunc("/api/v1/assets", s.assets)
	mux.HandleFunc("/api/v1/assets/metadata", s.assetMetadata)
	mux.HandleFunc("/api/v1/assets/risk-posture", s.assetRiskPosture)
	mux.HandleFunc("/api/v1/security/insights", s.securityInsights)
	mux.HandleFunc("/api/v1/security/incidents", s.securityIncidents)
	mux.HandleFunc("/api/v1/security/incident-context", s.securityIncidentContext)
	mux.HandleFunc("/api/v1/security/incident-status", s.securityIncidentStatus)
	mux.HandleFunc("/api/v1/security/incident-timeline", s.securityIncidentTimeline)
	mux.HandleFunc("/api/v1/security/incident-notes", s.securityIncidentNotes)
	mux.HandleFunc("/api/v1/security/rules", s.detectionRules)
	mux.HandleFunc("/api/v1/security/rule-findings", s.detectionRuleFindings)
	mux.HandleFunc("/api/v1/reports/overview", s.reportOverview)
	mux.HandleFunc("/api/v1/reports/overview/export", s.reportOverviewExport)
	mux.HandleFunc("/api/v1/ai/incident-summary", s.aiIncidentSummary)
	mux.HandleFunc("/api/v1/ai/asset-summary", s.aiAssetSummary)
	mux.HandleFunc("/api/v1/ai/report-summary", s.aiReportSummary)
	mux.HandleFunc("/api/v1/ai/capture-diagnostics-summary", s.aiCaptureDiagnosticsSummary)
	mux.HandleFunc("/api/v1/ai/query", s.aiQuery)
	mux.HandleFunc("/api/v1/ai/incident-investigation", s.aiIncidentInvestigation)
	mux.HandleFunc("/api/v1/ai/incident-actions", s.aiIncidentActions)
	mux.HandleFunc("/api/v1/ai/governance-suggestions", s.aiGovernanceSuggestions)
	mux.HandleFunc("/api/v1/ai/rule-effectiveness", s.aiRuleEffectiveness)
	mux.HandleFunc("/api/v1/ai/asset-enrichment-suggestions", s.aiAssetEnrichmentSuggestions)
	mux.HandleFunc("/api/v1/ai/approval-requests", s.aiApprovalRequests)
	mux.HandleFunc("/api/v1/ai/approval-stats", s.aiApprovalStats)
	mux.HandleFunc("/api/v1/ai/approval-requests/export", s.aiApprovalRequestsExport)
	mux.HandleFunc("/api/v1/collectors", s.collectors)
	mux.HandleFunc("/api/v1/collectors/config", s.collectorConfig)
	mux.HandleFunc("/api/v1/interfaces", s.interfaces)
	mux.HandleFunc("/api/v1/alerts", s.alerts)
	mux.HandleFunc("/api/v1/alerts/status", s.alertStatus)
	mux.HandleFunc("/api/v1/alerts/config", s.alertConfig)
	mux.HandleFunc("/api/v1/alerts/silences", s.alertSilences)
	mux.HandleFunc("/api/v1/system/status", s.status)
	mux.HandleFunc("/api/v1/system/data-quality", s.dataQuality)
	mux.HandleFunc("/api/v1/system/capture-quality", s.captureQuality)
	mux.HandleFunc("/api/v1/system/capture-diagnostics", s.captureDiagnostics)
	mux.HandleFunc("/api/v1/system/settings", s.systemSettings)
	mux.HandleFunc("/api/v1/system/settings/schema", s.systemSettingsSchema)
	mux.HandleFunc("/api/v1/system/settings/test-ai", s.systemSettingsTestAI)
	mux.HandleFunc("/api/v1/system/settings/test-webhook", s.systemSettingsTestWebhook)
	mux.HandleFunc("/api/v1/system/settings/export", s.systemSettingsExport)
	mux.HandleFunc("/api/v1/system/settings/import", s.systemSettingsImport)
	mux.HandleFunc("/api/v1/system/users", s.systemUsers)
	mux.HandleFunc("/api/v1/system/audit-events", s.auditEvents)
	mux.HandleFunc("/api/v1/system/audit-events/export", s.auditEventsExport)
	mux.HandleFunc("/api/v1/system/config-versions", s.configVersions)
	mux.HandleFunc("/api/v1/system/config-versions/export", s.configVersionsExport)
	mux.HandleFunc("/api/v1/system/config-version-diff", s.configVersionDiff)
	return cors(s.authRequired(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	statusData, statusErr := s.store.Status(r.Context())
	summary, summaryErr := s.store.Summary(r.Context(), 5)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	dbOK := 1
	if statusErr != nil || summaryErr != nil {
		dbOK = 0
	}
	collectorOnline := 0
	if collectorStatus(statusData) == "online" {
		collectorOnline = 1
	}
	_, _ = w.Write([]byte("# HELP nexaflow_database_ok ClickHouse query health.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_database_ok gauge\n"))
	_, _ = w.Write([]byte("nexaflow_database_ok " + strconv.Itoa(dbOK) + "\n"))
	_, _ = w.Write([]byte("# HELP nexaflow_collector_online Collector recent-window health.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_collector_online gauge\n"))
	_, _ = w.Write([]byte("nexaflow_collector_online " + strconv.Itoa(collectorOnline) + "\n"))
	_, _ = w.Write([]byte("# HELP nexaflow_latest_window_timestamp_seconds Latest collector window timestamp.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_latest_window_timestamp_seconds gauge\n"))
	_, _ = w.Write([]byte("nexaflow_latest_window_timestamp_seconds " + strconv.FormatInt(int64Value(statusData["latest_window_ts"]), 10) + "\n"))
	_, _ = w.Write([]byte("# HELP nexaflow_windows_24h_total Number of 5-second windows in the last 24 hours.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_windows_24h_total gauge\n"))
	_, _ = w.Write([]byte("nexaflow_windows_24h_total " + strconv.FormatInt(int64Value(statusData["windows_24h"]), 10) + "\n"))
	_, _ = w.Write([]byte("# HELP nexaflow_recent_bytes_total Recent traffic bytes over five minutes.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_recent_bytes_total gauge\n"))
	_, _ = w.Write([]byte("nexaflow_recent_bytes_total " + strconv.FormatInt(int64Value(summary["bytes"]), 10) + "\n"))
	_, _ = w.Write([]byte("# HELP nexaflow_recent_packets_total Recent traffic packets over five minutes.\n"))
	_, _ = w.Write([]byte("# TYPE nexaflow_recent_packets_total gauge\n"))
	_, _ = w.Write([]byte("nexaflow_recent_packets_total " + strconv.FormatInt(int64Value(summary["packets"]), 10) + "\n"))
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Summary(r.Context(), queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) topn(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dimension := q.Get("dimension")
	if dimension == "" {
		dimension = "ip"
	}
	direction := q.Get("direction")
	if direction == "" {
		direction = "src"
	}
	limit := 20
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	data, err := s.store.TopN(r.Context(), dimension, direction, limit, queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Timeseries(r.Context(), queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) ipProfile(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	data, err := s.store.IPProfile(r.Context(), ip, queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) portProfile(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(r.URL.Query().Get("port"))
	if port == "" {
		http.Error(w, "port is required", http.StatusBadRequest)
		return
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		http.Error(w, "port must be 1-65535", http.StatusBadRequest)
		return
	}
	data, err := s.store.PortProfile(r.Context(), port, queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) windows(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	data, err := s.store.Windows(r.Context(), queryMinutes(r), limit)
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) matrix(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Matrix(r.Context(), queryMinutes(r), queryLimit(r, 50, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) serviceMap(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ServiceMap(r.Context(), queryMinutes(r), queryLimit(r, 50, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) serviceAnalytics(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ServiceAnalytics(r.Context(), queryMinutes(r), queryLimit(r, 12, 50))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) serviceExposure(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ServiceExposure(r.Context(), queryMinutes(r), queryLimit(r, 50, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) externalAccess(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ExternalAccess(r.Context(), queryMinutes(r), queryLimit(r, 80, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) protocolTimeseries(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ProtocolTimeseries(r.Context(), queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) portTimeseries(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.PortTimeseries(r.Context(), queryMinutes(r), queryLimit(r, 8, 20))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) directionTimeseries(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.DirectionTimeseries(r.Context(), queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) dimensionTimeseries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dimension := strings.TrimSpace(q.Get("dimension"))
	if dimension == "" {
		dimension = "service"
	}
	key := strings.TrimSpace(q.Get("key"))
	direction := strings.TrimSpace(q.Get("direction"))
	data, err := s.store.DimensionTimeseries(r.Context(), dimension, key, direction, queryMinutes(r), queryLimit(r, 5, 20))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) objectRelations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dimension := strings.TrimSpace(q.Get("dimension"))
	if dimension == "" {
		dimension = "service"
	}
	key := strings.TrimSpace(q.Get("key"))
	direction := strings.TrimSpace(q.Get("direction"))
	data, err := s.store.ObjectRelations(r.Context(), dimension, key, direction, queryMinutes(r), queryLimit(r, 8, 30))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data, err := s.store.Sessions(r.Context(), q, queryMinutes(r), queryLimit(r, 80, 300))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data, err := s.store.Search(r.Context(), q, queryMinutes(r), queryLimit(r, 50, 200))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) trafficAnalysis(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.TrafficAnalysis(r.Context(), queryMinutes(r))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) trafficBaselineProfile(w http.ResponseWriter, r *http.Request) {
	minutes := queryMinutes(r)
	settings := s.loadSystemSettings()
	data, err := s.store.BehaviorBaseline(r.Context(), minutes, queryBaselineMinutes(r, minutes, settings.Analysis.BaselineMinutes), queryLimit(r, 10, 50))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) capacityPlanning(w http.ResponseWriter, r *http.Request) {
	bandwidth := s.loadSystemSettings().Analysis.BandwidthMbps
	if bandwidth == 0 {
		bandwidth = s.config.BandwidthMbps
	}
	data, err := s.store.CapacityPlanning(r.Context(), queryMinutes(r), queryLimit(r, 10, 50), bandwidth)
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) trafficChanges(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.TrafficChanges(r.Context(), queryMinutes(r), queryLimit(r, 30, 100))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) trafficAnomalies(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.TrafficAnomalies(r.Context(), queryMinutes(r), queryLimit(r, 30, 100))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Assets(r.Context(), queryMinutes(r), queryLimit(r, 50, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) assetMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data, err := s.store.AssetMetadata(r.Context(), strings.TrimSpace(r.URL.Query().Get("ip")))
		writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(stringValue(body["ip"])) == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	data, err := s.store.UpdateAssetMetadata(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "asset.metadata.update", "asset:"+stringValue(data["ip"]), "更新资产元数据："+stringValue(data["ip"]), map[string]any{
		"ip":          data["ip"],
		"name":        data["name"],
		"owner":       data["owner"],
		"business":    data["business"],
		"environment": data["environment"],
		"criticality": data["criticality"],
	})
	writeJSON(w, map[string]any{"data": data})
}

func (s *Server) assetRiskPosture(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.AssetRiskPosture(r.Context(), queryMinutes(r), queryLimit(r, 50, 300))
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	data = filterSilencedMaps(data, runtime.Alerts.SilencedSubjects, "ip")
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) securityInsights(w http.ResponseWriter, r *http.Request) {
	minutes := queryMinutes(r)
	limit := queryLimit(r, 50, 200)
	data, err := s.store.SecurityInsights(r.Context(), minutes, limit)
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	ruleRows, ruleErr := s.store.DetectionRuleFindings(r.Context(), runtime.Alerts.DetectionRules, minutes, limit)
	data = append(data, ruleRows...)
	data = filterSilencedMaps(data, runtime.Alerts.SilencedSubjects, "subject")
	sortSecurityRows(data)
	if len(data) > limit {
		data = data[:limit]
	}
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil || ruleErr != nil})
}

func (s *Server) securityIncidents(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r, 80, 300)
	minutes := queryMinutes(r)
	data, err := s.store.SecurityIncidents(r.Context(), minutes, limit)
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	ruleRows, ruleErr := s.store.DetectionRuleFindings(r.Context(), runtime.Alerts.DetectionRules, minutes, limit)
	for _, row := range ruleRows {
		data = append(data, ruleFindingIncident(row))
	}
	data = filterSilencedMaps(data, runtime.Alerts.SilencedSubjects, "subject")
	statusData, _ := s.store.Status(r.Context())
	if alert := collectorHealthAlert(s.config.CollectorID, statusData); alert.ID != "" && !isSilencedSubject(alert.Subject, runtime.Alerts.SilencedSubjects) {
		collectorRow := collectorIncident(alert)
		if overrides, overrideErr := s.store.AlertStatusOverrides(r.Context()); overrideErr == nil {
			if status := overrides[stringValue(collectorRow["id"])]; status != "" {
				collectorRow["status"] = status
			}
		}
		data = append([]map[string]any{collectorRow}, data...)
		if len(data) > limit {
			data = data[:limit]
		}
	}
	sortIncidentRows(data)
	if len(data) > limit {
		data = data[:limit]
	}
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil || ruleErr != nil})
}

func (s *Server) securityIncidentContext(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	data, err := s.store.SecurityIncidentContext(
		r.Context(),
		subject,
		strings.TrimSpace(r.URL.Query().Get("kind")),
		queryMinutes(r),
		queryLimit(r, 12, 50),
	)
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) securityIncidentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Note   string `json:"note"`
		Author string `json:"author"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateAlertStatus(r.Context(), strings.TrimSpace(body.ID), strings.TrimSpace(body.Status)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.Note) != "" {
		if _, err := s.store.AddIncidentNote(r.Context(), strings.TrimSpace(body.ID), strings.TrimSpace(body.Note), strings.TrimSpace(body.Author)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.audit(r, "incident.status.update", strings.TrimSpace(body.ID), "更新事件状态："+strings.TrimSpace(body.Status), map[string]any{
		"id":     strings.TrimSpace(body.ID),
		"status": strings.TrimSpace(body.Status),
		"note":   strings.TrimSpace(body.Note),
		"author": strings.TrimSpace(body.Author),
	})
	writeJSON(w, map[string]any{"data": map[string]string{"id": body.ID, "status": body.Status}})
}

func (s *Server) securityIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	data, err := s.store.IncidentTimeline(r.Context(), id, queryLimit(r, 50, 200))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) securityIncidentNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID     string `json:"id"`
		Note   string `json:"note"`
		Author string `json:"author"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := s.store.AddIncidentNote(r.Context(), strings.TrimSpace(body.ID), strings.TrimSpace(body.Note), strings.TrimSpace(body.Author))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(r, "incident.note.add", strings.TrimSpace(body.ID), "新增事件备注："+strings.TrimSpace(body.ID), map[string]any{
		"id":     strings.TrimSpace(body.ID),
		"author": strings.TrimSpace(body.Author),
	})
	writeJSON(w, map[string]any{"data": data})
}

func (s *Server) detectionRules(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"data": runtime.Alerts.DetectionRules})
	case http.MethodPost:
		var body model.DetectionRule
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.ID) == "" {
			body.ID = "rule-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		if strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.Metric) == "" || body.Threshold <= 0 {
			http.Error(w, "name, metric and threshold are required", http.StatusBadRequest)
			return
		}
		body.UpdatedAt = time.Now().Unix()
		runtime.Alerts.DetectionRules = upsertDetectionRule(runtime.Alerts.DetectionRules, body)
		if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.configSnapshot(r, "rules", strings.TrimSpace(body.ID), "detection_rule.upsert", "保存检测规则："+strings.TrimSpace(body.Name), config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
		s.audit(r, "detection_rule.upsert", strings.TrimSpace(body.ID), "保存检测规则："+strings.TrimSpace(body.Name), map[string]any{
			"id":        body.ID,
			"name":      body.Name,
			"metric":    body.Metric,
			"operator":  body.Operator,
			"threshold": body.Threshold,
			"severity":  body.Severity,
			"enabled":   body.Enabled,
		})
		writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)).Alerts.DetectionRules})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			var body struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			id = strings.TrimSpace(body.ID)
		}
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		runtime.Alerts.DetectionRules = removeDetectionRule(runtime.Alerts.DetectionRules, id)
		if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.configSnapshot(r, "rules", id, "detection_rule.delete", "删除检测规则："+id, config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
		s.audit(r, "detection_rule.delete", id, "删除检测规则："+id, map[string]any{"id": id})
		writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)).Alerts.DetectionRules})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) detectionRuleFindings(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	data, err := s.store.DetectionRuleFindings(r.Context(), runtime.Alerts.DetectionRules, queryMinutes(r), queryLimit(r, 50, 200))
	data = filterSilencedMaps(data, runtime.Alerts.SilencedSubjects, "subject")
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) reportOverview(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ReportOverview(r.Context(), queryMinutes(r), queryLimit(r, 10, 50))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) reportOverviewExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.loadSystemSettings().Data.ExportEnabled {
		http.Error(w, "export is disabled", http.StatusForbidden)
		return
	}
	minutes := queryMinutes(r)
	limit := queryLimit(r, 50, 200)
	data, err := s.store.ReportOverview(r.Context(), minutes, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	body, err := reportOverviewCSV(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("nexaflow-overview-report-%dm-%s.csv", minutes, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(body); err == nil {
		s.audit(r, "report.export", "overview", "导出巡检报表："+filename, map[string]any{
			"format":  "csv",
			"minutes": minutes,
			"limit":   limit,
			"bytes":   len(body),
		})
	}
}

func reportOverviewCSV(report map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buf)
	write := func(values ...string) {
		_ = writer.Write(values)
	}
	summary := mapValue(report["summary"])
	write("section", "object", "level_status", "metric", "bytes", "packets_sessions", "summary", "recommendation")
	write(
		"summary",
		"overview",
		"",
		fmt.Sprintf("avg_mbps=%.2f peak_mbps=%.2f p95_mbps=%.2f utilization=%.6f", float64Value(summary["avg_mbps"]), float64Value(summary["peak_mbps"]), float64Value(summary["p95_mbps"]), float64Value(summary["utilization"])),
		strconv.FormatUint(uint64Value(summary["bytes"]), 10),
		strconv.FormatUint(uint64Value(summary["packets"]), 10),
		fmt.Sprintf("assets=%d critical_assets=%d open_incidents=%d anomalies=%d exposed_services=%d external_access=%d", int64Value(summary["asset_count"]), int64Value(summary["critical_assets"]), int64Value(summary["open_incidents"]), int64Value(summary["anomaly_count"]), int64Value(summary["exposed_services"]), int64Value(summary["external_access"])),
		"",
	)
	for _, item := range sliceValue(report["recommendations"]) {
		row := mapValue(item)
		write("recommendation", stringValue(row["title"]), stringValue(row["level"]), "", "", "", stringValue(row["detail"]), stringValue(row["detail"]))
	}
	for _, item := range sliceValue(report["asset_risks"]) {
		row := mapValue(item)
		object := strings.TrimSpace(stringValue(row["ip"]) + " " + firstString(stringValue(row["name"]), stringValue(row["business"])))
		write("asset_risk", object, stringValue(row["risk_level"]), fmt.Sprintf("score=%d exposed=%d incidents=%d", int64Value(row["risk_score"]), int64Value(row["exposed_services"]), int64Value(row["open_incidents"])), strconv.FormatUint(uint64Value(row["total_bytes"]), 10), strconv.FormatUint(uint64Value(row["total_packets"]), 10), stringValue(row["top_finding"]), stringValue(row["recommended_action"]))
	}
	for _, item := range sliceValue(report["incidents"]) {
		row := mapValue(item)
		write("incident", stringValue(row["subject"]), stringValue(row["severity"])+"/"+stringValue(row["status"]), stringValue(row["source"])+"/"+stringValue(row["kind"])+"/score="+strconv.FormatInt(int64Value(row["score"]), 10), strconv.FormatUint(uint64Value(row["bytes"]), 10), strconv.FormatUint(uint64Value(row["packets"]), 10), stringValue(row["summary"]), stringValue(row["recommended_action"]))
	}
	for _, item := range sliceValue(report["anomalies"]) {
		row := mapValue(item)
		write("anomaly", stringValue(row["dimension"])+"/"+stringValue(row["key"]), stringValue(row["severity"]), stringValue(row["kind"])+"/change="+fmt.Sprintf("%.2f", float64Value(row["change_ratio"]))+"/score="+strconv.FormatInt(int64Value(row["score"]), 10), strconv.FormatUint(uint64Value(row["current_bytes"]), 10), strconv.FormatUint(uint64Value(row["current_packets"]), 10), stringValue(row["summary"]), "confirm planned change or drill down into object profile")
	}
	for _, item := range sliceValue(report["exposures"]) {
		row := mapValue(item)
		write("service_exposure", stringValue(row["ip"])+":"+stringValue(row["port"])+"/"+stringValue(row["protocol"]), stringValue(row["risk"]), stringValue(row["service"])+"/"+stringValue(row["category"])+"/"+stringValue(row["direction"]), strconv.FormatUint(uint64Value(row["bytes"]), 10), strconv.FormatUint(uint64Value(row["packets"]), 10), stringValue(row["sample_flow"]), "review service owner, source range and firewall policy")
	}
	for _, item := range sliceValue(report["external_access"]) {
		row := mapValue(item)
		write("external_access", stringValue(row["public_ip"])+" -> "+stringValue(row["internal_ip"])+":"+stringValue(row["port"]), stringValue(row["risk"]), stringValue(row["direction"])+"/"+stringValue(row["service"])+"/"+stringValue(row["category"]), strconv.FormatUint(uint64Value(row["bytes"]), 10), strconv.FormatInt(int64Value(row["session_count"]), 10), stringValue(row["sample_flow"]), "review public peer trust and session volume")
	}
	for _, section := range []struct {
		name string
		key  string
	}{
		{name: "top_src", key: "top_src"},
		{name: "top_ports", key: "top_ports"},
		{name: "top_services", key: "top_services"},
	} {
		for _, item := range sliceValue(report[section.key]) {
			row := mapValue(item)
			write(section.name, stringValue(row["key"]), "", "", strconv.FormatUint(uint64Value(row["bytes"]), 10), strconv.FormatUint(uint64Value(row["packets"]), 10), "", "")
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) aiIncidentSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 12, 50))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	incidents, incidentErr := s.store.SecurityIncidents(r.Context(), minutes, max(limit, 20))
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	ruleRows, ruleErr := s.store.DetectionRuleFindings(r.Context(), runtime.Alerts.DetectionRules, minutes, max(limit, 20))
	for _, row := range ruleRows {
		incidents = append(incidents, ruleFindingIncident(row))
	}
	incidents = filterSilencedMaps(incidents, runtime.Alerts.SilencedSubjects, "subject")
	sortIncidentRows(incidents)
	incident := findAIIncident(incidents, id, subject, kind)
	if subject == "" {
		subject = stringValue(incident["subject"])
	}
	if kind == "" {
		kind = stringValue(incident["kind"])
	}
	if subject == "" {
		http.Error(w, "subject or id is required", http.StatusBadRequest)
		return
	}
	contextData, contextErr := s.store.SecurityIncidentContext(r.Context(), subject, kind, minutes, limit)
	data, aiErr := s.enhanceAISummary(r.Context(), buildAIIncidentSummary(s.aiOptions(), incident, contextData), map[string]any{
		"incident": incident,
		"context":  contextData,
		"minutes":  minutes,
	})
	writeJSON(w, map[string]any{
		"data":     data,
		"degraded": incidentErr != nil || ruleErr != nil || (contextErr != nil && !aiIncidentContextUsable(contextData)) || aiErr != nil,
	})
}

func (s *Server) aiAssetSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 20, 200))
	risks, riskErr := s.store.AssetRiskPosture(r.Context(), minutes, limit)
	profile, profileErr := s.store.IPProfile(r.Context(), ip, minutes)
	risk := findMapByString(risks, "ip", ip)
	data, aiErr := s.enhanceAISummary(r.Context(), buildAIAssetSummary(s.aiOptions(), ip, risk, profile), map[string]any{
		"ip":      ip,
		"risk":    risk,
		"profile": profile,
		"minutes": minutes,
	})
	writeJSON(w, map[string]any{
		"data":     data,
		"degraded": riskErr != nil || profileErr != nil || aiErr != nil,
	})
}

func (s *Server) aiReportSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	report, err := s.store.ReportOverview(r.Context(), minutes, s.aiContextLimit(queryLimit(r, 10, 50)))
	data, aiErr := s.enhanceAISummary(r.Context(), buildAIReportSummary(s.aiOptions(), report), map[string]any{
		"report":  report,
		"minutes": minutes,
	})
	writeJSON(w, map[string]any{
		"data":     data,
		"degraded": err != nil || aiErr != nil,
	})
}

func (s *Server) aiCaptureDiagnosticsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := queryLimit(r, 20, 200)
	capture, captureErr := s.store.CaptureQuality(r.Context(), minutes, limit)
	quality, qualityErr := s.store.DataQuality(r.Context(), minutes, limit)
	report := captureDiagnosticReport(capture, quality, minutes)
	data, aiErr := s.enhanceAISummary(r.Context(), buildAICaptureDiagnosticsSummary(s.aiOptions(), report), map[string]any{
		"capture_diagnostics": report,
		"capture_quality":     capture,
		"data_quality":        quality,
		"minutes":             minutes,
	})
	writeJSON(w, map[string]any{
		"data":     data,
		"degraded": captureErr != nil || qualityErr != nil || aiErr != nil,
	})
}

func (s *Server) aiQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Question string `json:"question"`
		Minutes  int    `json:"minutes"`
		Limit    int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	question := strings.TrimSpace(request.Question)
	if question == "" {
		http.Error(w, "question is required", http.StatusBadRequest)
		return
	}
	minutes := normalizeQueryMinutes(request.Minutes)
	minutes = aiQueryMinutes(question, minutes)
	limit := request.Limit
	if limit <= 0 {
		limit = 8
	}
	limit = s.aiContextLimit(min(max(limit, 3), 30))
	intent := parseAIQueryIntent(question, minutes, limit)
	result, err := s.runAIQuery(r.Context(), intent)
	result["degraded"] = err != nil
	if err != nil {
		result["error"] = err.Error()
	}
	writeJSON(w, map[string]any{"data": result, "degraded": err != nil})
}

func (s *Server) aiIncidentInvestigation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 12, 50))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	id := strings.TrimSpace(r.URL.Query().Get("id"))

	var (
		incidents   []map[string]any
		contextData map[string]any
		timeline    []map[string]any
		history     []map[string]any

		incidentErr error
		contextErr  error
		timelineErr error
		historyErr  error
	)
	historyMinutes := min(max(minutes*2, 30), 60)
	contextStarted := subject != "" && kind != ""
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		incidents, incidentErr = s.collectSecurityIncidents(r.Context(), minutes, max(limit, 20))
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		history, historyErr = s.collectSecurityIncidents(r.Context(), historyMinutes, max(limit, 20))
	}()
	if contextStarted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			contextData, contextErr = s.store.SecurityIncidentContext(r.Context(), subject, kind, minutes, limit)
		}()
	}
	if id != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timeline, timelineErr = s.store.IncidentTimeline(r.Context(), id, 20)
		}()
	}
	wg.Wait()

	incident := findAIIncident(incidents, id, subject, kind)
	if subject == "" {
		subject = stringValue(incident["subject"])
	}
	if kind == "" {
		kind = stringValue(incident["kind"])
	}
	if subject == "" {
		http.Error(w, "subject or id is required", http.StatusBadRequest)
		return
	}
	if !contextStarted {
		contextData, contextErr = s.store.SecurityIncidentContext(r.Context(), subject, kind, minutes, limit)
	}
	similar := findSimilarAIIncidents(incident, history, limit)
	degradedReasons := aiIncidentDegradedReasons(incidentErr, contextErr, contextData, timelineErr, historyErr)
	writeJSON(w, map[string]any{
		"data":     buildAIIncidentInvestigation(s.aiOptions(), incident, contextData, timeline, similar, degradedReasons),
		"degraded": len(degradedReasons) > 0,
	})
}

func (s *Server) aiGovernanceSuggestions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 8, 30))
	report, reportErr := s.store.ReportOverview(r.Context(), minutes, limit)
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	suggestions := buildAIGovernanceSuggestions(s.aiOptions(), report, runtime.Alerts, minutes, limit)
	writeJSON(w, map[string]any{"data": suggestions, "degraded": reportErr != nil})
}

func (s *Server) aiIncidentActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 8, 30))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	id := strings.TrimSpace(r.URL.Query().Get("id"))

	var (
		incidents   []map[string]any
		contextData map[string]any
		history     []map[string]any

		incidentErr error
		contextErr  error
		historyErr  error
	)
	historyMinutes := min(max(minutes*2, 30), 60)
	contextStarted := subject != "" && kind != ""
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		incidents, incidentErr = s.collectSecurityIncidents(r.Context(), minutes, max(limit, 20))
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		history, historyErr = s.collectSecurityIncidents(r.Context(), historyMinutes, max(limit, 20))
	}()
	if contextStarted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			contextData, contextErr = s.store.SecurityIncidentContext(r.Context(), subject, kind, minutes, limit)
		}()
	}
	wg.Wait()

	incident := findAIIncident(incidents, id, subject, kind)
	if subject == "" {
		subject = stringValue(incident["subject"])
	}
	if kind == "" {
		kind = stringValue(incident["kind"])
	}
	if subject == "" {
		http.Error(w, "subject or id is required", http.StatusBadRequest)
		return
	}
	if !contextStarted {
		contextData, contextErr = s.store.SecurityIncidentContext(r.Context(), subject, kind, minutes, limit)
	}
	similar := findSimilarAIIncidents(incident, history, limit)
	degradedReasons := aiIncidentDegradedReasons(incidentErr, contextErr, contextData, nil, historyErr)
	investigation := buildAIIncidentInvestigation(s.aiOptions(), incident, contextData, nil, similar, degradedReasons)
	result := buildAIIncidentActionSuggestions(s.aiOptions(), incident, contextData, investigation, minutes, limit)
	writeJSON(w, map[string]any{"data": result, "degraded": len(degradedReasons) > 0})
}

func (s *Server) aiRuleEffectiveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 100, 500))
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	findings, err := s.store.DetectionRuleFindings(r.Context(), runtime.Alerts.DetectionRules, minutes, limit)
	result := buildAIRuleEffectiveness(s.aiOptions(), runtime.Alerts.DetectionRules, findings, runtime.Alerts, minutes)
	writeJSON(w, map[string]any{"data": result, "degraded": err != nil})
}

func (s *Server) aiAssetEnrichmentSuggestions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	limit := s.aiContextLimit(queryLimit(r, 8, 50))
	risks, err := s.store.AssetRiskPosture(r.Context(), minutes, max(limit, 20))
	result := buildAIAssetEnrichmentSuggestions(s.aiOptions(), risks, minutes, limit)
	writeJSON(w, map[string]any{"data": result, "degraded": err != nil})
}

func (s *Server) collectors(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	statusData, _ := s.store.Status(r.Context())
	status := collectorStatus(statusData)
	writeJSON(w, map[string]any{
		"data": []map[string]any{{
			"id":           s.config.CollectorID,
			"source_id":    runtime.SourceID,
			"status":       status,
			"mode":         runtime.Mode,
			"iface":        runtime.Iface,
			"bpf_filter":   runtime.BPFFilter,
			"pcap_file":    runtime.PcapFile,
			"replay_speed": runtime.ReplaySpeed,
			"session_topn": runtime.SessionTopN,
			"updated_at":   runtime.UpdatedAt,
		}},
	})
}

func (s *Server) collectorConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body config.CaptureRuntime
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	current := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	if body.Mode == "" {
		body.Mode = current.Mode
	}
	if body.Iface == "" {
		body.Iface = current.Iface
	}
	if body.BPFFilter == "" {
		body.BPFFilter = current.BPFFilter
	}
	if body.PcapFile == "" {
		body.PcapFile = current.PcapFile
	}
	if body.ReplaySpeed <= 0 {
		body.ReplaySpeed = current.ReplaySpeed
	}
	if body.SessionTopN <= 0 {
		body.SessionTopN = current.SessionTopN
	}
	if alertsEmpty(body.Alerts) {
		body.Alerts = current.Alerts
	}
	if body.SourceID == "" && body.Mode != "" && body.Iface != "" {
		body.SourceID = body.Mode + "-" + body.Iface
	}
	if err := config.SaveRuntime(s.config.RuntimePath, body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.configSnapshot(r, "collector", s.config.CollectorID, "collector.config.update", "更新采集器配置："+body.Mode+" / "+body.Iface, config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
	s.audit(r, "collector.config.update", s.config.CollectorID, "更新采集器配置："+body.Mode+" / "+body.Iface, map[string]any{
		"collector_id": s.config.CollectorID,
		"mode":         body.Mode,
		"iface":        body.Iface,
		"source_id":    body.SourceID,
		"bpf_filter":   body.BPFFilter,
		"pcap_file":    body.PcapFile,
		"replay_speed": body.ReplaySpeed,
		"session_topn": body.SessionTopN,
	})
	writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))})
}

func (s *Server) interfaces(w http.ResponseWriter, _ *http.Request) {
	root := s.config.HostNetPath
	entries, err := os.ReadDir(root)
	if err != nil {
		writeJSON(w, map[string]any{"data": []any{}, "error": err.Error()})
		return
	}
	items := []map[string]string{{"name": "any", "state": "up", "type": "pseudo"}}
	for _, entry := range entries {
		if skipInterface(entry.Name()) {
			continue
		}
		state := readSmall(filepath.Join(root, entry.Name(), "operstate"))
		if state == "" {
			state = "unknown"
		}
		items = append(items, map[string]string{"name": entry.Name(), "state": state, "type": "interface"})
	}
	writeJSON(w, map[string]any{"data": items})
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	data, err := s.store.Alerts(r.Context(), limit, queryMinutes(r))
	statusData, _ := s.store.Status(r.Context())
	if alert := collectorHealthAlert(s.config.CollectorID, statusData); alert.ID != "" {
		data = append([]model.AlertEvent{alert}, data...)
		if len(data) > limit {
			data = data[:limit]
		}
	}
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) alertStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateAlertStatus(r.Context(), strings.TrimSpace(body.ID), strings.TrimSpace(body.Status)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(r, "alert.status.update", strings.TrimSpace(body.ID), "更新告警状态："+strings.TrimSpace(body.Status), map[string]any{
		"id":     strings.TrimSpace(body.ID),
		"status": strings.TrimSpace(body.Status),
	})
	writeJSON(w, map[string]any{"data": map[string]string{"id": body.ID, "status": body.Status}})
}

func (s *Server) alertConfig(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"data": runtime.Alerts})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body config.Alerts
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	runtime.Alerts = body
	if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.configSnapshot(r, "alerts", s.config.CollectorID, "alert.config.update", "更新告警阈值配置", config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
	s.audit(r, "alert.config.update", s.config.CollectorID, "更新告警阈值配置", map[string]any{
		"flow_bytes":       runtime.Alerts.FlowBytes,
		"flow_share":       runtime.Alerts.FlowShare,
		"source_packets":   runtime.Alerts.SourcePackets,
		"link_utilization": runtime.Alerts.LinkUtilization,
	})
	writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)).Alerts})
}

func (s *Server) alertSilences(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"data": runtime.Alerts.SilencedSubjects})
		return
	}
	var body struct {
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(body.Subject)
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		runtime.Alerts.SilencedSubjects = append(runtime.Alerts.SilencedSubjects, subject)
	case http.MethodDelete:
		runtime.Alerts.SilencedSubjects = removeString(runtime.Alerts.SilencedSubjects, subject)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "alert.silence.add"
	summary := "加入白名单/静默名单：" + subject
	if r.Method == http.MethodDelete {
		action = "alert.silence.remove"
		summary = "移出白名单/静默名单：" + subject
	}
	s.configSnapshot(r, "alerts", subject, action, summary, config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
	s.audit(r, action, subject, summary, map[string]any{"subject": subject})
	writeJSON(w, map[string]any{"data": config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)).Alerts.SilencedSubjects})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	data, err := s.store.Status(r.Context())
	if data == nil {
		data = map[string]any{}
	}
	status := collectorStatus(data)
	data["collector"] = map[string]any{
		"id":           s.config.CollectorID,
		"source_id":    runtime.SourceID,
		"status":       status,
		"mode":         runtime.Mode,
		"iface":        runtime.Iface,
		"bpf_filter":   runtime.BPFFilter,
		"pcap_file":    runtime.PcapFile,
		"replay_speed": runtime.ReplaySpeed,
		"session_topn": runtime.SessionTopN,
		"alerts":       runtime.Alerts,
		"updated_at":   runtime.UpdatedAt,
	}
	data["ops"] = platformOpsStatus(s.config, s.loadSystemSettings(), stringValue(data["database"]), status)
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func platformOpsStatus(cfg config.Config, settings config.SystemSettings, databaseStatus, collectorStatus string) map[string]any {
	runtimePath := strings.TrimSpace(cfg.RuntimePath)
	if runtimePath == "" {
		runtimePath = "/var/lib/nexaflow/runtime.json"
	}
	runtimeDir := filepath.Dir(runtimePath)
	disks := []map[string]any{}
	seen := map[string]bool{}
	for _, item := range []struct {
		label string
		path  string
	}{
		{label: "运行目录", path: runtimeDir},
		{label: "根目录", path: "/"},
	} {
		path := filepath.Clean(item.path)
		if seen[path] {
			continue
		}
		seen[path] = true
		disks = append(disks, diskUsageSnapshot(item.label, path))
	}

	resources := systemResourceSnapshot()
	services := platformServiceChecks(cfg, runtimePath, databaseStatus, collectorStatus)
	deployment := platformDeploymentSnapshot(cfg, settings)
	status := platformOpsAggregateStatus(disks, resources, services)
	retention := map[string]any{
		"clickhouse_retention_days": settings.Data.ClickHouseRetentionDays,
		"session_retention_days":    settings.Data.SessionRetentionDays,
		"audit_retention_days":      settings.Data.AuditRetentionDays,
		"config_version_limit":      settings.Data.ConfigVersionLimit,
		"export_enabled":            settings.Data.ExportEnabled,
	}
	return map[string]any{
		"generated_at":     time.Now().Unix(),
		"status":           status,
		"summary":          platformOpsSummary(status),
		"runtime_path":     runtimePath,
		"runtime_dir":      runtimeDir,
		"disks":            disks,
		"resources":        resources,
		"services":         services,
		"deployment":       deployment,
		"data_retention":   retention,
		"recommendations":  platformOpsRecommendations(status, disks, resources, services, settings),
		"deployment_hints": []string{"部署前确认公网端口与防火墙策略", "磁盘高水位时优先清理 Docker 构建缓存和旧镜像", "生产环境建议将 ClickHouse 数据目录挂载到独立数据盘", "生产验证建议固定 Git 提交、镜像标签和配置版本，便于回滚。"},
	}
}

func systemResourceSnapshot() map[string]any {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return map[string]any{
			"status": "unavailable",
			"error":  err.Error(),
		}
	}
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	totalMemory := info.Totalram * unit
	freeMemory := info.Freeram * unit
	usedMemory := totalMemory - freeMemory
	memoryRatio := float64(0)
	if totalMemory > 0 {
		memoryRatio = float64(usedMemory) / float64(totalMemory)
	}
	cpus := goruntime.NumCPU()
	load1 := float64(info.Loads[0]) / 65536
	load5 := float64(info.Loads[1]) / 65536
	load15 := float64(info.Loads[2]) / 65536
	memStatus := usageStatus(memoryRatio)
	loadState := loadStatus(load1, cpus)
	status := "ok"
	if memStatus == "critical" || loadState == "critical" {
		status = "critical"
	} else if memStatus == "warning" || loadState == "warning" {
		status = "warning"
	}
	return map[string]any{
		"status":             status,
		"memory_status":      memStatus,
		"load_status":        loadState,
		"total_memory_bytes": totalMemory,
		"used_memory_bytes":  usedMemory,
		"free_memory_bytes":  freeMemory,
		"memory_used_ratio":  memoryRatio,
		"load1":              load1,
		"load5":              load5,
		"load15":             load15,
		"cpu_count":          cpus,
		"uptime_seconds":     info.Uptime,
		"process_count":      info.Procs,
	}
}

func platformServiceChecks(cfg config.Config, runtimePath, databaseStatus, collectorStatus string) []map[string]any {
	runtimeState := "ok"
	runtimeDetail := "运行配置文件可访问"
	if _, err := os.Stat(runtimePath); err != nil {
		runtimeState = "warning"
		runtimeDetail = "运行配置文件暂不可访问：" + err.Error()
	}
	return []map[string]any{
		{
			"name":       "API Server",
			"role":       "控制台 API 与状态聚合",
			"status":     "ok",
			"detail":     "当前请求由 API 服务正常处理",
			"endpoint":   cfg.APIAddr,
			"actionable": false,
		},
		{
			"name":       "ClickHouse",
			"role":       "流量窗口与会话数据存储",
			"status":     databaseServiceStatus(databaseStatus),
			"detail":     "数据库状态：" + databaseStatus,
			"endpoint":   maskConnectionString(cfg.ClickHouseURL),
			"actionable": databaseStatus != "ok",
		},
		{
			"name":       "Collector",
			"role":       "真实流量采集与窗口写入",
			"status":     collectorServiceStatus(collectorStatus),
			"detail":     "采集器状态：" + collectorStatus,
			"endpoint":   cfg.Iface,
			"actionable": collectorStatus != "online",
		},
		tcpServiceCheck("Redis", cfg.RedisAddr, "缓存与采集队列"),
		{
			"name":       "Runtime Config",
			"role":       "采集、告警和系统配置持久化",
			"status":     runtimeState,
			"detail":     runtimeDetail,
			"endpoint":   runtimePath,
			"actionable": runtimeState != "ok",
		},
	}
}

func tcpServiceCheck(name, addr, role string) map[string]any {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return map[string]any{"name": name, "role": role, "status": "unknown", "detail": "未配置连接地址", "endpoint": "", "actionable": true}
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return map[string]any{"name": name, "role": role, "status": "warning", "detail": "TCP 探测失败：" + err.Error(), "endpoint": addr, "actionable": true}
	}
	_ = conn.Close()
	return map[string]any{"name": name, "role": role, "status": "ok", "detail": "TCP 探测可达", "endpoint": addr, "actionable": false}
}

func platformDeploymentSnapshot(cfg config.Config, settings config.SystemSettings) map[string]any {
	hostname, _ := os.Hostname()
	return map[string]any{
		"hostname":       hostname,
		"in_container":   fileExists("/.dockerenv"),
		"os":             goruntime.GOOS,
		"arch":           goruntime.GOARCH,
		"go_version":     goruntime.Version(),
		"cpu_count":      goruntime.NumCPU(),
		"api_addr":       cfg.APIAddr,
		"redis_addr":     cfg.RedisAddr,
		"clickhouse_url": maskConnectionString(cfg.ClickHouseURL),
		"database":       cfg.Database,
		"auth_enabled":   settings.Security.AuthEnabled,
		"ai_mode":        settings.AI.Mode,
		"ai_provider":    settings.AI.Provider,
		"build_version":  strings.TrimSpace(os.Getenv("NEXAFLOW_VERSION")),
		"git_commit":     strings.TrimSpace(os.Getenv("NEXAFLOW_GIT_COMMIT")),
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func diskUsageSnapshot(label, path string) map[string]any {
	statPath := firstExistingPath(path)
	var stat syscall.Statfs_t
	if err := syscall.Statfs(statPath, &stat); err != nil {
		return map[string]any{
			"label":       label,
			"path":        path,
			"stat_path":   statPath,
			"status":      "unavailable",
			"total_bytes": uint64(0),
			"used_bytes":  uint64(0),
			"free_bytes":  uint64(0),
			"used_ratio":  float64(0),
			"error":       err.Error(),
		}
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	if total == 0 {
		return map[string]any{
			"label":       label,
			"path":        path,
			"stat_path":   statPath,
			"status":      "unavailable",
			"total_bytes": uint64(0),
			"used_bytes":  uint64(0),
			"free_bytes":  uint64(0),
			"used_ratio":  float64(0),
			"error":       "statfs returned zero blocks",
		}
	}
	used := total - free
	ratio := float64(used) / float64(total)
	return map[string]any{
		"label":       label,
		"path":        path,
		"stat_path":   statPath,
		"status":      diskUsageStatus(ratio),
		"total_bytes": total,
		"used_bytes":  used,
		"free_bytes":  free,
		"used_ratio":  ratio,
	}
}

func firstExistingPath(path string) string {
	current := filepath.Clean(path)
	for {
		if _, err := os.Stat(current); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return current
		}
		current = parent
	}
}

func diskUsageStatus(ratio float64) string {
	return usageStatus(ratio)
}

func usageStatus(ratio float64) string {
	switch {
	case ratio >= 0.9:
		return "critical"
	case ratio >= 0.8:
		return "warning"
	default:
		return "ok"
	}
}

func loadStatus(load1 float64, cpus int) string {
	if cpus <= 0 {
		cpus = 1
	}
	switch {
	case load1 >= float64(cpus)*2:
		return "critical"
	case load1 >= float64(cpus):
		return "warning"
	default:
		return "ok"
	}
}

func platformOpsAggregateStatus(disks []map[string]any, resources map[string]any, services []map[string]any) string {
	status := "ok"
	for _, disk := range disks {
		switch stringValue(disk["status"]) {
		case "critical":
			return "critical"
		case "warning":
			if status == "ok" {
				status = "warning"
			}
		case "unavailable":
			if status == "ok" {
				status = "degraded"
			}
		}
	}
	switch stringValue(resources["status"]) {
	case "critical":
		return "critical"
	case "warning":
		if status == "ok" {
			status = "warning"
		}
	case "unavailable":
		if status == "ok" {
			status = "degraded"
		}
	}
	for _, service := range services {
		switch stringValue(service["status"]) {
		case "critical":
			return "critical"
		case "warning":
			if status == "ok" {
				status = "warning"
			}
		}
	}
	return status
}

func platformOpsSummary(status string) string {
	switch status {
	case "critical":
		return "存在严重运行风险，请优先检查资源水位、服务健康和磁盘容量"
	case "warning":
		return "存在运维预警，建议提前处理资源、服务或容量风险"
	case "degraded":
		return "部分运行状态不可用，请检查目录挂载和权限"
	default:
		return "运行状态正常，资源和容量处于可控范围"
	}
}

func platformOpsRecommendations(status string, disks []map[string]any, resources map[string]any, services []map[string]any, settings config.SystemSettings) []string {
	recommendations := []string{}
	diskCritical := false
	diskWarning := false
	for _, disk := range disks {
		switch stringValue(disk["status"]) {
		case "critical":
			diskCritical = true
		case "warning":
			diskWarning = true
		}
	}
	if diskCritical {
		recommendations = append(recommendations, "磁盘使用率超过 90%，请立即清理 Docker 构建缓存、旧镜像和无用容器，并评估扩容。")
	} else if diskWarning {
		recommendations = append(recommendations, "磁盘使用率超过 80%，建议安排清理窗口并检查 ClickHouse 数据保留策略。")
	}
	if settings.Data.ClickHouseRetentionDays > 30 {
		recommendations = append(recommendations, "ClickHouse 保留天数超过 30 天，生产环境建议结合数据盘容量和查询需求重新评估。")
	}
	if settings.Data.SessionRetentionDays > 30 {
		recommendations = append(recommendations, "会话明细保留天数超过 30 天，建议定期归档或降低明细留存周期。")
	}
	for _, disk := range disks {
		if stringValue(disk["status"]) == "unavailable" && stringValue(disk["error"]) != "" {
			recommendations = append(recommendations, fmt.Sprintf("%s 状态不可读：%s", stringValue(disk["label"]), stringValue(disk["error"])))
		}
	}
	if stringValue(resources["memory_status"]) == "warning" || stringValue(resources["memory_status"]) == "critical" {
		recommendations = append(recommendations, "内存水位偏高，请检查 ClickHouse、构建任务和采集器资源占用，必要时增加内存或调整查询窗口。")
	}
	if stringValue(resources["load_status"]) == "warning" || stringValue(resources["load_status"]) == "critical" {
		recommendations = append(recommendations, "系统负载偏高，请核对实时采集、前端构建和数据库查询是否并发过高。")
	}
	for _, service := range services {
		if boolValue(service["actionable"]) {
			recommendations = append(recommendations, fmt.Sprintf("%s 需要关注：%s", stringValue(service["name"]), stringValue(service["detail"])))
		}
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "当前无需紧急处理，建议保留定期磁盘巡检和备份验证。")
	}
	return recommendations
}

func databaseServiceStatus(status string) string {
	if status == "ok" {
		return "ok"
	}
	if status == "" {
		return "unknown"
	}
	return "critical"
}

func collectorServiceStatus(status string) string {
	switch status {
	case "online":
		return "ok"
	case "degraded", "offline":
		return "warning"
	case "":
		return "unknown"
	default:
		return status
	}
}

func maskConnectionString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return value
	}
	username := parsed.User.Username()
	if _, ok := parsed.User.Password(); ok {
		parsed.User = url.UserPassword(username, "****")
	}
	return parsed.String()
}

func (s *Server) dataQuality(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.DataQuality(r.Context(), queryMinutes(r), queryLimit(r, 20, 200))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) captureQuality(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.CaptureQuality(r.Context(), queryMinutes(r), queryLimit(r, 20, 200))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) captureDiagnostics(w http.ResponseWriter, r *http.Request) {
	minutes := queryMinutes(r)
	limit := queryLimit(r, 20, 200)
	capture, captureErr := s.store.CaptureQuality(r.Context(), minutes, limit)
	quality, qualityErr := s.store.DataQuality(r.Context(), minutes, limit)
	writeJSON(w, map[string]any{
		"data":     captureDiagnosticReport(capture, quality, minutes),
		"degraded": captureErr != nil || qualityErr != nil,
	})
}

func (s *Server) systemSettings(w http.ResponseWriter, r *http.Request) {
	path := s.systemSettingsPath()
	current := s.loadSystemSettings()
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"data": s.publicSystemSettings(current)})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body config.SystemSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	next := mergeSensitiveSystemSettings(current, body)
	if err := config.SaveSystemSettings(path, next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	saved := s.loadSystemSettings()
	s.configSnapshot(r, "system", "settings", "system.settings.update", "更新系统设置", s.publicSystemSettings(saved))
	s.audit(r, "system.settings.update", "settings", "更新系统设置", map[string]any{
		"ai_mode":          saved.AI.Mode,
		"ai_provider":      saved.AI.Provider,
		"ai_model":         saved.AI.Model,
		"default_minutes":  saved.Analysis.DefaultMinutes,
		"baseline_minutes": saved.Analysis.BaselineMinutes,
		"auth_enabled":     saved.Security.AuthEnabled,
		"notify_enabled":   saved.Notification.Enabled,
	})
	writeJSON(w, map[string]any{"data": s.publicSystemSettings(saved)})
}

func (s *Server) systemSettingsSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"ai_modes":       []string{"disabled", "local_mock", "openai"},
		"ai_providers":   []string{"local_mock", "openai", "deepseek", "qwen", "openai_compatible"},
		"default_ranges": []int{5, 15, 60, 360, 1440},
		"severities":     []string{"info", "warning", "critical"},
		"providers":      []string{"webhook", "feishu", "dingtalk", "wechat_work"},
		"hot_reload":     []string{"ai", "analysis", "security", "notification", "data"},
		"restart_required": []string{
			"backend.api_addr",
			"backend.clickhouse_url",
			"backend.redis_addr",
			"backend.database",
		},
	}})
}

func (s *Server) systemSettingsTestAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	settings, err := s.decodeSettingsCandidate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := s.testAISettings(r.Context(), settings.AI)
	writeJSON(w, map[string]any{"data": result})
}

func (s *Server) systemSettingsTestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	settings, err := s.decodeSettingsCandidate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := testWebhookSettings(r.Context(), settings.Notification)
	writeJSON(w, map[string]any{"data": result})
}

func (s *Server) systemSettingsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"data": s.publicSystemSettings(s.loadSystemSettings())})
}

func (s *Server) systemSettingsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body config.SystemSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	next := mergeSensitiveSystemSettings(s.loadSystemSettings(), body)
	if err := config.SaveSystemSettings(s.systemSettingsPath(), next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	saved := s.loadSystemSettings()
	s.configSnapshot(r, "system", "settings", "system.settings.import", "导入系统设置", s.publicSystemSettings(saved))
	s.audit(r, "system.settings.import", "settings", "导入系统设置", map[string]any{"updated_at": saved.UpdatedAt})
	writeJSON(w, map[string]any{"data": s.publicSystemSettings(saved)})
}

func (s *Server) systemUsers(w http.ResponseWriter, r *http.Request) {
	settings := s.loadSystemSettings()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"data": map[string]any{
			"users":   publicUserAccounts(settings.Security.Users),
			"summary": userAccountSummary(settings.Security.Users),
			"roles":   []string{"admin", "analyst", "auditor", "viewer"},
			"statuses": []string{
				"active",
				"disabled",
			},
		}})
	case http.MethodPost:
		var body struct {
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
			Status      string `json:"status"`
			Password    string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		username := strings.TrimSpace(body.Username)
		if username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		role := config.NormalizeUserRole(body.Role)
		status := config.NormalizeUserStatus(body.Status)
		now := time.Now().Unix()
		users := settings.Security.Users
		found := -1
		for idx := range users {
			if users[idx].Username == username {
				found = idx
				break
			}
		}
		passwordHash := ""
		if strings.TrimSpace(body.Password) != "" {
			hash, err := hashPassword(body.Password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			passwordHash = hash
		}
		if found < 0 && passwordHash == "" {
			http.Error(w, "password is required for new user", http.StatusBadRequest)
			return
		}
		if found >= 0 {
			users[found].DisplayName = strings.TrimSpace(body.DisplayName)
			if users[found].DisplayName == "" {
				users[found].DisplayName = username
			}
			users[found].Role = role
			users[found].Status = status
			users[found].UpdatedAt = now
			if passwordHash != "" {
				users[found].PasswordHash = passwordHash
			}
		} else {
			users = append(users, config.UserAccount{
				Username:     username,
				DisplayName:  strings.TrimSpace(body.DisplayName),
				Role:         role,
				Status:       status,
				PasswordHash: passwordHash,
				CreatedAt:    now,
				UpdatedAt:    now,
			})
		}
		users = normalizeUserSettings(users)
		if !hasWritableAdmin(users) {
			http.Error(w, "at least one active admin user is required", http.StatusBadRequest)
			return
		}
		settings.Security.Users = users
		if err := config.SaveSystemSettings(s.systemSettingsPath(), settings); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		saved := s.loadSystemSettings()
		action := "system.user.upsert"
		s.configSnapshot(r, "system", "users", action, "保存用户："+username, map[string]any{"users": publicUserAccounts(saved.Security.Users)})
		s.audit(r, action, "user:"+username, "保存用户："+username, map[string]any{"username": username, "role": role, "status": status})
		writeJSON(w, map[string]any{"data": map[string]any{
			"users":   publicUserAccounts(saved.Security.Users),
			"summary": userAccountSummary(saved.Security.Users),
		}})
	case http.MethodDelete:
		username := strings.TrimSpace(r.URL.Query().Get("username"))
		if username == "" {
			var body struct {
				Username string `json:"username"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			username = strings.TrimSpace(body.Username)
		}
		if username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		users := []config.UserAccount{}
		removed := false
		for _, user := range settings.Security.Users {
			if user.Username == username {
				removed = true
				continue
			}
			users = append(users, user)
		}
		if !removed {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if len(users) > 0 && !hasWritableAdmin(users) {
			http.Error(w, "at least one active admin user is required", http.StatusBadRequest)
			return
		}
		settings.Security.Users = normalizeUserSettings(users)
		if err := config.SaveSystemSettings(s.systemSettingsPath(), settings); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		saved := s.loadSystemSettings()
		action := "system.user.delete"
		s.configSnapshot(r, "system", "users", action, "删除用户："+username, map[string]any{"users": publicUserAccounts(saved.Security.Users)})
		s.audit(r, action, "user:"+username, "删除用户："+username, map[string]any{"username": username})
		writeJSON(w, map[string]any{"data": map[string]any{
			"users":   publicUserAccounts(saved.Security.Users),
			"summary": userAccountSummary(saved.Security.Users),
		}})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.AuditEvents(r.Context(), queryLimit(r, 80, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) auditEventsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.loadSystemSettings().Data.ExportEnabled {
		http.Error(w, "export is disabled", http.StatusForbidden)
		return
	}
	limit := queryLimit(r, 200, 2000)
	data, err := s.store.AuditEvents(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	body, err := auditEventsCSV(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("nexaflow-audit-events-%s.csv", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(body); err == nil {
		s.audit(r, "audit.export", "operation_audit", "导出审计日志："+filename, map[string]any{
			"format": "csv",
			"limit":  limit,
			"rows":   len(data),
			"bytes":  len(body),
		})
	}
}

func auditEventsCSV(events []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"time", "actor", "action", "target", "summary", "client_ip", "detail"}); err != nil {
		return nil, err
	}
	for _, row := range events {
		detail := firstString(stringValue(row["detail_text"]), stringValue(row["detail"]))
		if err := writer.Write([]string{
			time.Unix(int64Value(row["ts"]), 0).Format(time.RFC3339),
			stringValue(row["actor"]),
			stringValue(row["action"]),
			stringValue(row["target"]),
			stringValue(row["summary"]),
			stringValue(row["client_ip"]),
			detail,
		}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) configVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data, err := s.store.ConfigVersions(r.Context(), strings.TrimSpace(r.URL.Query().Get("scope")), queryLimit(r, 80, 500))
		writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(body.ID)
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	version, err := s.store.ConfigVersion(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var runtime config.CaptureRuntime
	if err := json.Unmarshal([]byte(stringValue(version["config"])), &runtime); err != nil {
		http.Error(w, "invalid config snapshot: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	restored := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	target := stringValue(version["target"])
	if target == "" {
		target = s.config.CollectorID
	}
	scope := stringValue(version["scope"])
	if scope == "" {
		scope = "runtime"
	}
	summary := "恢复配置版本：" + id
	s.configSnapshot(r, scope, target, "config.version.restore", summary, restored)
	s.audit(r, "config.version.restore", target, summary, map[string]any{
		"version_id": id,
		"scope":      scope,
		"source_ts":  version["ts"],
		"source":     version["summary"],
	})
	writeJSON(w, map[string]any{"data": restored, "version": version})
}

func (s *Server) configVersionsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.loadSystemSettings().Data.ExportEnabled {
		http.Error(w, "export is disabled", http.StatusForbidden)
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	limit := queryLimit(r, 200, 2000)
	data, err := s.store.ConfigVersions(r.Context(), scope, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	body, err := configVersionsCSV(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scopePart := "all"
	if scope != "" {
		scopePart = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, scope)
	}
	filename := fmt.Sprintf("nexaflow-config-versions-%s-%s.csv", scopePart, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(body); err == nil {
		s.audit(r, "config.version.export", "config_versions", "导出配置版本："+filename, map[string]any{
			"format": "csv",
			"scope":  scope,
			"limit":  limit,
			"rows":   len(data),
			"bytes":  len(body),
		})
	}
}

func configVersionsCSV(versions []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"time", "id", "actor", "scope", "target", "action", "summary", "client_ip", "config"}); err != nil {
		return nil, err
	}
	for _, row := range versions {
		configText := firstString(stringValue(row["config_text"]), stringValue(row["config"]))
		if err := writer.Write([]string{
			time.Unix(int64Value(row["ts"]), 0).Format(time.RFC3339),
			stringValue(row["id"]),
			stringValue(row["actor"]),
			stringValue(row["scope"]),
			stringValue(row["target"]),
			stringValue(row["action"]),
			stringValue(row["summary"]),
			stringValue(row["client_ip"]),
			configText,
		}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Server) configVersionDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	version, err := s.store.ConfigVersion(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(stringValue(version["config"])), &snapshot); err != nil {
		http.Error(w, "invalid config snapshot: "+err.Error(), http.StatusBadRequest)
		return
	}
	currentJSON, err := json.Marshal(config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var current map[string]any
	if err := json.Unmarshal(currentJSON, &current); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	changes := configDiffRows(snapshot, current)
	writeJSON(w, map[string]any{
		"data": map[string]any{
			"version_id": id,
			"summary": map[string]any{
				"change_count": len(changes),
				"source":       version["summary"],
				"source_ts":    version["ts"],
				"current_ts":   current["updated_at"],
			},
			"changes": changes,
		},
	})
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	enabled := s.authEnabled()
	authenticated := true
	actor := "operator"
	role := authRoleAdmin
	if enabled {
		identity, ok := s.verifyAuthRequest(r)
		authenticated = ok
		actor = identity.Actor
		role = identity.Role
	}
	if actor == "" {
		actor = "operator"
	}
	if role == "" {
		role = authRoleAdmin
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"enabled":         enabled,
		"authenticated":   authenticated,
		"actor":           actor,
		"role":            role,
		"can_write":       !enabled || (authenticated && boolCapability(role, "can_write")),
		"can_export":      !enabled || (authenticated && boolCapability(role, "can_export")),
		"can_audit":       !enabled || (authenticated && boolCapability(role, "can_audit")),
		"can_configure":   !enabled || (authenticated && boolCapability(role, "can_configure")),
		"can_investigate": !enabled || (authenticated && boolCapability(role, "can_investigate")),
	}})
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authEnabled() {
		writeJSON(w, map[string]any{"data": map[string]any{"enabled": false, "authenticated": true, "actor": "operator", "role": authRoleAdmin, "can_write": true, "can_export": true, "can_audit": true, "can_configure": true, "can_investigate": true}})
		return
	}
	var body struct {
		Actor    string `json:"actor"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	identity, ok := s.loginIdentity(body.Actor, body.Password)
	if !ok {
		s.recordUserLoginFailure(body.Actor)
		if s.store != nil {
			_ = s.store.RecordAuditEvent(r.Context(), strings.TrimSpace(body.Actor), "auth.login.failed", "console", "控制台登录失败："+strings.TrimSpace(body.Actor), map[string]any{"actor": strings.TrimSpace(body.Actor)}, auditClientIP(r))
		}
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	if err := s.setAuthCookie(w, identity.Actor, identity.Role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordUserLogin(identity.Actor)
	if s.store != nil {
		_ = s.store.RecordAuditEvent(r.Context(), identity.Actor, "auth.login", "console", "控制台登录："+identity.Actor, map[string]any{"actor": identity.Actor, "role": identity.Role}, auditClientIP(r))
	}
	data := map[string]any{"enabled": true, "authenticated": true, "actor": identity.Actor, "role": identity.Role}
	for key, value := range roleCapabilities(identity.Role) {
		data[key] = value
	}
	writeJSON(w, map[string]any{"data": data})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	identity, _ := s.verifyAuthRequest(r)
	if identity.Actor == "" {
		identity.Actor = "operator"
	}
	if identity.Role == "" {
		identity.Role = authRoleAdmin
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	if s.authEnabled() {
		if s.store != nil {
			_ = s.store.RecordAuditEvent(r.Context(), identity.Actor, "auth.logout", "console", "控制台退出："+identity.Actor, map[string]any{"actor": identity.Actor, "role": identity.Role}, auditClientIP(r))
		}
	}
	writeJSON(w, map[string]any{"data": map[string]any{"enabled": s.authEnabled(), "authenticated": false, "actor": "", "role": "", "can_write": false, "can_export": false, "can_audit": false, "can_configure": false, "can_investigate": false}})
}

func (s *Server) authRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() || !strings.HasPrefix(r.URL.Path, "/api/v1/") || strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		identity, ok := s.verifyAuthRequest(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		permission := requestPermission(r)
		if !roleAllows(identity.Role, permission) {
			http.Error(w, "permission denied: "+permission, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), actorContextKey, identity.Actor)
		ctx = context.WithValue(ctx, roleContextKey, identity.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authEnabled() bool {
	security := s.loadSystemSettings().Security
	return security.AuthEnabled && (strings.TrimSpace(security.AdminPassword) != "" || strings.TrimSpace(security.ReadOnlyPassword) != "" || hasActiveUsers(security.Users))
}

func (s *Server) loginRole(password string) string {
	security := s.loadSystemSettings().Security
	if strings.TrimSpace(security.AdminPassword) != "" && subtle.ConstantTimeCompare([]byte(password), []byte(security.AdminPassword)) == 1 {
		return authRoleAdmin
	}
	if security.ReadOnlyEnabled && strings.TrimSpace(security.ReadOnlyPassword) != "" && subtle.ConstantTimeCompare([]byte(password), []byte(security.ReadOnlyPassword)) == 1 {
		return authRoleViewer
	}
	return ""
}

func (s *Server) loginIdentity(actor, password string) (authIdentity, bool) {
	security := s.loadSystemSettings().Security
	username := strings.TrimSpace(actor)
	for _, user := range security.Users {
		if user.Status != "active" || strings.TrimSpace(user.PasswordHash) == "" {
			continue
		}
		if username != "" && user.Username != username {
			continue
		}
		if user.LockedUntil > time.Now().Unix() {
			return authIdentity{}, false
		}
		if verifyPasswordHash(password, user.PasswordHash) {
			return authIdentity{Actor: user.Username, Role: normalizeAuthRole(user.Role)}, true
		}
	}
	if role := s.loginRole(password); role != "" {
		if username == "" {
			username = "operator"
		}
		return authIdentity{Actor: username, Role: role}, true
	}
	return authIdentity{}, false
}

func (s *Server) recordUserLogin(username string) {
	if strings.TrimSpace(username) == "" {
		return
	}
	path := s.systemSettingsPath()
	settings := s.loadSystemSettings()
	changed := false
	now := time.Now().Unix()
	for idx := range settings.Security.Users {
		if settings.Security.Users[idx].Username == username {
			settings.Security.Users[idx].LastLoginAt = now
			settings.Security.Users[idx].FailedLogins = 0
			settings.Security.Users[idx].LockedUntil = 0
			settings.Security.Users[idx].UpdatedAt = now
			changed = true
			break
		}
	}
	if changed {
		_ = config.SaveSystemSettings(path, settings)
	}
}

func (s *Server) recordUserLoginFailure(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	path := s.systemSettingsPath()
	settings := s.loadSystemSettings()
	changed := false
	now := time.Now().Unix()
	limit := settings.Security.MaxLoginFailures
	lockoutSeconds := int64(settings.Security.LockoutMinutes * 60)
	for idx := range settings.Security.Users {
		if settings.Security.Users[idx].Username != username {
			continue
		}
		settings.Security.Users[idx].FailedLogins++
		settings.Security.Users[idx].UpdatedAt = now
		if limit > 0 && settings.Security.Users[idx].FailedLogins >= limit {
			settings.Security.Users[idx].LockedUntil = now + lockoutSeconds
		}
		changed = true
		break
	}
	if changed {
		_ = config.SaveSystemSettings(path, settings)
	}
}

func requestPermission(r *http.Request) string {
	path := r.URL.Path
	method := r.Method
	if method == http.MethodOptions || method == http.MethodHead {
		return "read"
	}
	if strings.HasPrefix(path, "/api/v1/system/audit-events") || strings.HasPrefix(path, "/api/v1/system/config-version") || path == "/api/v1/system/config-versions" {
		if method == http.MethodGet {
			return "audit"
		}
		return "configure"
	}
	if strings.Contains(path, "/export") {
		return "export"
	}
	if strings.HasPrefix(path, "/api/v1/system/settings") || path == "/api/v1/system/users" || path == "/api/v1/collectors/config" || path == "/api/v1/alerts/config" || path == "/api/v1/alerts/silences" || path == "/api/v1/security/rules" {
		if method == http.MethodGet {
			return "read"
		}
		return "configure"
	}
	if path == "/api/v1/security/incident-status" || path == "/api/v1/security/incident-notes" || path == "/api/v1/alerts/status" || strings.HasPrefix(path, "/api/v1/ai/approval-requests") {
		if method == http.MethodGet {
			return "read"
		}
		return "investigate"
	}
	if path == "/api/v1/assets/metadata" {
		if method == http.MethodGet {
			return "read"
		}
		return "investigate"
	}
	if method == http.MethodGet {
		return "read"
	}
	if path == "/api/v1/ai/query" {
		return "read"
	}
	return "write"
}

func roleAllows(role, permission string) bool {
	role = normalizeAuthRole(role)
	switch permission {
	case "read":
		return true
	case "export":
		return boolCapability(role, "can_export")
	case "audit":
		return boolCapability(role, "can_audit")
	case "configure":
		return boolCapability(role, "can_configure")
	case "investigate":
		return boolCapability(role, "can_investigate")
	case "write":
		return boolCapability(role, "can_write")
	default:
		return false
	}
}

func normalizeAuthRole(role string) string {
	switch config.NormalizeUserRole(role) {
	case authRoleAdmin:
		return authRoleAdmin
	case "analyst":
		return "analyst"
	case "auditor":
		return "auditor"
	default:
		return authRoleViewer
	}
}

func hasActiveUsers(users []config.UserAccount) bool {
	for _, user := range users {
		if user.Status == "active" && strings.TrimSpace(user.PasswordHash) != "" {
			return true
		}
	}
	return false
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := passwordDigest(salt, password)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(salt) + ":" + base64.RawURLEncoding.EncodeToString(sum), nil
}

func verifyPasswordHash(password, encoded string) bool {
	parts := strings.Split(encoded, ":")
	if len(parts) != 3 || parts[0] != "sha256" {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	actual := passwordDigest(salt, password)
	return hmac.Equal(actual, expected)
}

func passwordDigest(salt []byte, password string) []byte {
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(password))
	return h.Sum(nil)
}

func (s *Server) setAuthCookie(w http.ResponseWriter, actor, role string) error {
	ttl := s.authSessionTTL()
	token, err := s.signAuthToken(actor, role, time.Now().Add(ttl).Unix())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) authSessionTTL() time.Duration {
	hours := s.loadSystemSettings().Security.SessionTTLHours
	if hours <= 0 {
		hours = 12
	}
	if hours > 168 {
		hours = 168
	}
	return time.Duration(hours) * time.Hour
}

func (s *Server) signAuthToken(actor, role string, expires int64) (string, error) {
	role = normalizeAuthRole(role)
	payload := actor + "|" + role + "|" + strconv.FormatInt(expires, 10)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := s.authSignature(encodedPayload)
	return encodedPayload + "." + sig, nil
}

func (s *Server) verifyAuthRequest(r *http.Request) (authIdentity, bool) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return authIdentity{}, false
	}
	return s.verifyAuthToken(cookie.Value)
}

func (s *Server) verifyAuthToken(token string) (authIdentity, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return authIdentity{}, false
	}
	expected := s.authSignature(parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return authIdentity{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authIdentity{}, false
	}
	payload := strings.Split(string(raw), "|")
	if len(payload) != 2 && len(payload) != 3 {
		return authIdentity{}, false
	}
	role := authRoleAdmin
	expiresRaw := payload[1]
	if len(payload) == 3 {
		role = normalizeAuthRole(payload[1])
		expiresRaw = payload[2]
	}
	expires, err := strconv.ParseInt(expiresRaw, 10, 64)
	if err != nil || expires < time.Now().Unix() {
		return authIdentity{}, false
	}
	actor := strings.TrimSpace(payload[0])
	if actor == "" {
		actor = "operator"
	}
	return authIdentity{Actor: actor, Role: role}, true
}

func (s *Server) authSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte(s.authSecret()))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) authSecret() string {
	if secret := strings.TrimSpace(s.config.AuthSecret); secret != "" {
		return secret
	}
	return s.config.AuthPassword
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func skipInterface(name string) bool {
	return name == "lo" || strings.HasPrefix(name, "veth")
}

func readSmall(path string) string {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) && !errorsIsPermission(err) {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func errorsIsPermission(err error) bool {
	return err != nil && (os.IsPermission(err) || err == fs.ErrPermission)
}

func queryMinutes(r *http.Request) int {
	minutes := 15
	if raw := r.URL.Query().Get("minutes"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 5 && n <= 1440 {
			minutes = n
		}
	}
	return minutes
}

func queryBaselineMinutes(r *http.Request, minutes, configured int) int {
	fallback := configured
	if fallback <= 0 {
		fallback = max(minutes*8, 60)
	}
	if fallback > 1440 {
		fallback = 1440
	}
	value := fallback
	if raw := r.URL.Query().Get("baseline_minutes"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= minutes*2 && n <= 10080 {
			value = n
		}
	}
	return value
}

func queryLimit(r *http.Request, fallback, max int) int {
	limit := fallback
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= max {
			limit = n
		}
	}
	return limit
}

func (s *Server) audit(r *http.Request, action, target, summary string, detail map[string]any) {
	if s.store == nil {
		return
	}
	_ = s.store.RecordAuditEvent(r.Context(), auditActor(r), action, target, summary, detail, auditClientIP(r))
}

func (s *Server) configSnapshot(r *http.Request, scope, target, action, summary string, snapshot any) {
	if s.store == nil {
		return
	}
	_ = s.store.RecordConfigVersion(r.Context(), auditActor(r), scope, target, action, summary, snapshot, auditClientIP(r))
}

func configDiffRows(before, after map[string]any) []map[string]string {
	left := map[string]string{}
	right := map[string]string{}
	flattenConfigValue("", before, left)
	flattenConfigValue("", after, right)
	paths := map[string]bool{}
	for path := range left {
		paths[path] = true
	}
	for path := range right {
		paths[path] = true
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	changes := []map[string]string{}
	for _, path := range ordered {
		beforeValue, beforeOK := left[path]
		afterValue, afterOK := right[path]
		if beforeOK && afterOK && beforeValue == afterValue {
			continue
		}
		kind := "changed"
		if !beforeOK {
			kind = "added"
		}
		if !afterOK {
			kind = "removed"
		}
		changes = append(changes, map[string]string{
			"path":   path,
			"type":   kind,
			"before": beforeValue,
			"after":  afterValue,
		})
	}
	return changes
}

func flattenConfigValue(prefix string, value any, out map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 && prefix != "" {
			out[prefix] = "{}"
			return
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flattenConfigValue(path, typed[key], out)
		}
	case []any:
		if len(typed) == 0 && prefix != "" {
			out[prefix] = "[]"
			return
		}
		for index, item := range typed {
			flattenConfigValue(prefix+"["+strconv.Itoa(index)+"]", item, out)
		}
	default:
		if prefix == "" {
			prefix = "$"
		}
		out[prefix] = configValueText(value)
	}
}

func configValueText(value any) string {
	if value == nil {
		return "null"
	}
	if text, ok := value.(string); ok {
		return text
	}
	data, err := json.Marshal(value)
	if err != nil {
		return stringValue(value)
	}
	return string(data)
}

func (s *Server) systemSettingsPath() string {
	return config.SystemSettingsPath(s.config.RuntimePath)
}

func (s *Server) loadSystemSettings() config.SystemSettings {
	return config.LoadSystemSettings(s.systemSettingsPath(), config.DefaultSystemSettings(s.config))
}

func (s *Server) publicSystemSettings(settings config.SystemSettings) map[string]any {
	return map[string]any{
		"ai": map[string]any{
			"mode":              settings.AI.Mode,
			"provider":          settings.AI.Provider,
			"model":             settings.AI.Model,
			"base_url":          settings.AI.BaseURL,
			"api_key_set":       strings.TrimSpace(settings.AI.APIKey) != "",
			"api_key_masked":    maskSecret(settings.AI.APIKey),
			"max_context_rows":  settings.AI.MaxContextRows,
			"timeout_seconds":   settings.AI.TimeoutSeconds,
			"temperature":       settings.AI.Temperature,
			"enabled_summaries": settings.AI.EnabledSummaries,
		},
		"analysis": settings.Analysis,
		"security": map[string]any{
			"auth_enabled":            settings.Security.AuthEnabled,
			"readonly_enabled":        settings.Security.ReadOnlyEnabled,
			"admin_password_set":      strings.TrimSpace(settings.Security.AdminPassword) != "",
			"readonly_password_set":   strings.TrimSpace(settings.Security.ReadOnlyPassword) != "",
			"session_ttl_hours":       settings.Security.SessionTTLHours,
			"max_login_failures":      settings.Security.MaxLoginFailures,
			"lockout_minutes":         settings.Security.LockoutMinutes,
			"require_audit_for_write": settings.Security.RequireAuditForWrite,
			"allow_frontend_secrets":  settings.Security.AllowFrontendSecrets,
		},
		"notification": map[string]any{
			"enabled":              settings.Notification.Enabled,
			"provider":             settings.Notification.Provider,
			"webhook_url":          settings.Notification.WebhookURL,
			"webhook_token_set":    strings.TrimSpace(settings.Notification.WebhookToken) != "",
			"webhook_token_masked": maskSecret(settings.Notification.WebhookToken),
			"min_severity":         settings.Notification.MinSeverity,
			"notify_on_incident":   settings.Notification.NotifyOnIncident,
			"notify_on_report":     settings.Notification.NotifyOnReport,
			"channels":             settings.Notification.Channels,
		},
		"data":       settings.Data,
		"backend":    settings.Backend,
		"updated_at": settings.UpdatedAt,
	}
}

func publicUserAccounts(users []config.UserAccount) []map[string]any {
	items := []map[string]any{}
	for _, user := range normalizeUserSettings(users) {
		items = append(items, map[string]any{
			"username":           user.Username,
			"display_name":       user.DisplayName,
			"role":               user.Role,
			"status":             user.Status,
			"password_set":       strings.TrimSpace(user.PasswordHash) != "",
			"created_at":         user.CreatedAt,
			"updated_at":         user.UpdatedAt,
			"last_login_at":      user.LastLoginAt,
			"failed_login_count": user.FailedLogins,
			"locked_until":       user.LockedUntil,
			"locked":             user.LockedUntil > time.Now().Unix(),
			"can_write":          user.Status == "active" && boolCapability(user.Role, "can_write"),
			"can_export":         user.Status == "active" && boolCapability(user.Role, "can_export"),
			"can_audit":          user.Status == "active" && boolCapability(user.Role, "can_audit"),
			"can_configure":      user.Status == "active" && boolCapability(user.Role, "can_configure"),
			"can_investigate":    user.Status == "active" && boolCapability(user.Role, "can_investigate"),
		})
	}
	return items
}

func roleCapabilities(role string) map[string]bool {
	role = normalizeAuthRole(role)
	return map[string]bool{
		"can_write":       role == authRoleAdmin,
		"can_export":      role == authRoleAdmin || role == "analyst" || role == "auditor",
		"can_audit":       role == authRoleAdmin || role == "auditor",
		"can_configure":   role == authRoleAdmin,
		"can_investigate": role == authRoleAdmin || role == "analyst",
	}
}

func boolCapability(role, capability string) bool {
	return roleCapabilities(role)[capability]
}

func userAccountSummary(users []config.UserAccount) map[string]any {
	summary := map[string]any{
		"total":    len(users),
		"active":   0,
		"disabled": 0,
		"admin":    0,
		"analyst":  0,
		"auditor":  0,
		"viewer":   0,
	}
	for _, user := range normalizeUserSettings(users) {
		if user.Status == "active" {
			summary["active"] = int64Value(summary["active"]) + 1
		} else {
			summary["disabled"] = int64Value(summary["disabled"]) + 1
		}
		role := config.NormalizeUserRole(user.Role)
		summary[role] = int64Value(summary[role]) + 1
	}
	return summary
}

func normalizeUserSettings(users []config.UserAccount) []config.UserAccount {
	data, _ := json.Marshal(config.SecuritySettings{Users: users})
	var security config.SecuritySettings
	_ = json.Unmarshal(data, &security)
	settings := config.DefaultSystemSettings(config.Config{})
	settings.Security.Users = security.Users
	settings = config.LoadSystemSettings("", settings)
	return settings.Security.Users
}

func hasWritableAdmin(users []config.UserAccount) bool {
	for _, user := range normalizeUserSettings(users) {
		if user.Status == "active" && user.Role == authRoleAdmin && strings.TrimSpace(user.PasswordHash) != "" {
			return true
		}
	}
	return false
}

func mergeSensitiveSystemSettings(current, next config.SystemSettings) config.SystemSettings {
	if strings.TrimSpace(next.AI.APIKey) == "" || isMaskedSecret(next.AI.APIKey) {
		next.AI.APIKey = current.AI.APIKey
	}
	if strings.TrimSpace(next.Security.AdminPassword) == "" || isMaskedSecret(next.Security.AdminPassword) {
		next.Security.AdminPassword = current.Security.AdminPassword
	}
	if strings.TrimSpace(next.Security.ReadOnlyPassword) == "" || isMaskedSecret(next.Security.ReadOnlyPassword) {
		next.Security.ReadOnlyPassword = current.Security.ReadOnlyPassword
	}
	if strings.TrimSpace(next.Notification.WebhookToken) == "" || isMaskedSecret(next.Notification.WebhookToken) {
		next.Notification.WebhookToken = current.Notification.WebhookToken
	}
	if next.Security.Users == nil {
		next.Security.Users = current.Security.Users
	}
	return next
}

func (s *Server) decodeSettingsCandidate(r *http.Request) (config.SystemSettings, error) {
	current := s.loadSystemSettings()
	var body config.SystemSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return current, err
	}
	return mergeSensitiveSystemSettings(current, body), nil
}

func (s *Server) testAISettings(ctx context.Context, ai config.AISettings) map[string]any {
	result := map[string]any{
		"ok":       true,
		"mode":     ai.Mode,
		"provider": ai.Provider,
		"model":    ai.Model,
		"message":  "本地摘要模式可用。",
	}
	if ai.Mode == "disabled" {
		result["ok"] = false
		result["message"] = "AI 已关闭，启用 local_mock 或外部模型后再测试。"
		return result
	}
	if ai.Mode == "local_mock" {
		return result
	}
	if strings.TrimSpace(ai.BaseURL) == "" || strings.TrimSpace(ai.APIKey) == "" {
		result["ok"] = false
		result["message"] = "外部模型需要配置 Base URL 和 API Key。"
		return result
	}
	base, err := url.Parse(strings.TrimRight(ai.BaseURL, "/") + "/models")
	if err != nil || base.Scheme == "" || base.Host == "" {
		result["ok"] = false
		result["message"] = "Base URL 格式不正确。"
		return result
	}
	timeout := time.Duration(ai.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		result["ok"] = false
		result["message"] = err.Error()
		return result
	}
	req.Header.Set("Authorization", "Bearer "+ai.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		result["ok"] = false
		result["message"] = "连接模型网关失败：" + err.Error()
		return result
	}
	defer resp.Body.Close()
	result["status"] = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result["message"] = "模型网关连接成功。"
		return result
	}
	result["ok"] = false
	result["message"] = "模型网关返回异常状态：" + resp.Status
	return result
}

func testWebhookSettings(ctx context.Context, notification config.NotificationSettings) map[string]any {
	result := map[string]any{"ok": false, "provider": notification.Provider, "message": "通知未启用或 Webhook URL 为空。"}
	if !notification.Enabled || strings.TrimSpace(notification.WebhookURL) == "" {
		return result
	}
	target, err := url.Parse(notification.WebhookURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		result["message"] = "Webhook URL 格式不正确。"
		return result
	}
	body := `{"source":"nexaflow","type":"settings_test","severity":"info","message":"NexaFlow 通知测试"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(body))
	if err != nil {
		result["message"] = err.Error()
		return result
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(notification.WebhookToken) != "" {
		req.Header.Set("Authorization", "Bearer "+notification.WebhookToken)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result["message"] = "Webhook 发送失败：" + err.Error()
		return result
	}
	defer resp.Body.Close()
	result["status"] = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result["ok"] = true
		result["message"] = "Webhook 测试发送成功。"
		return result
	}
	result["message"] = "Webhook 返回异常状态：" + resp.Status
	return result
}

func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}

func isMaskedSecret(secret string) bool {
	secret = strings.TrimSpace(secret)
	return secret == "****" || strings.Contains(secret, "****")
}

func captureDiagnosticReport(capture, quality map[string]any, minutes int) map[string]any {
	captureSummary := mapValue(capture["summary"])
	qualitySummary := mapValue(quality["summary"])
	captureSources := sliceValue(capture["sources"])
	now := time.Now().Unix()

	rxDrops := uint64Value(captureSummary["rx_dropped"])
	txDrops := uint64Value(captureSummary["tx_dropped"])
	rxErrors := uint64Value(captureSummary["rx_errors"])
	txErrors := uint64Value(captureSummary["tx_errors"])
	dropRatio := float64Value(captureSummary["drop_ratio"])
	errorRatio := float64Value(captureSummary["error_ratio"])
	packetPressure := maxCaptureSourcePressure(captureSources, "packet_queue_pressure")
	if packetPressure == 0 {
		packetPressure = float64Value(captureSummary["queue_pressure"])
	}
	windowPressure := maxCaptureSourcePressure(captureSources, "window_queue_pressure")
	if windowPressure == 0 {
		windowPressure = float64Value(captureSummary["queue_pressure"])
	}
	freshness := int64Value(qualitySummary["freshness_seconds"])
	if freshness == 0 {
		freshness = maxCaptureSourceFreshness(captureSources)
	}
	coverage := float64Value(qualitySummary["coverage_ratio"])

	layers := []map[string]any{
		diagnosticLayer(
			"interface_counters",
			"网卡接口计数",
			statusByCounters(rxDrops+txDrops, rxErrors+txErrors, dropRatio, errorRatio),
			scoreByRatio(maxFloat(dropRatio, errorRatio)),
			fmt.Sprintf("Dropped %d / Errors %d", rxDrops+txDrops, rxErrors+txErrors),
			fmt.Sprintf("丢包率 %.4f%%，错误率 %.4f%%，用于判断内核网卡计数是否异常。", dropRatio*100, errorRatio*100),
			"检查物理链路、网卡驱动、交换机端口和服务器内核日志，必要时提升采集机规格。",
		),
		diagnosticLayer(
			"packet_queue",
			"用户态包队列",
			statusByUpperThreshold(packetPressure, 0.7, 0.9),
			scoreByRatio(packetPressure),
			fmt.Sprintf("队列压力 %.1f%%", packetPressure*100),
			"反映抓包线程到聚合线程之间的包队列堆积，持续升高会导致采样延迟或丢包。",
			"减少过滤范围、提升 packet_queue_capacity，或增加采集进程 CPU 配额。",
		),
		diagnosticLayer(
			"window_queue",
			"窗口写入队列",
			statusByUpperThreshold(windowPressure, 0.7, 0.9),
			scoreByRatio(windowPressure),
			fmt.Sprintf("队列压力 %.1f%%", windowPressure*100),
			"反映窗口聚合结果写入 ClickHouse 前的堆积，持续升高通常意味着存储写入或网络链路变慢。",
			"检查 ClickHouse 写入延迟、批量窗口配置和服务器磁盘 IO。",
		),
		diagnosticLayer(
			"freshness",
			"数据新鲜度",
			statusByUpperThreshold(float64(freshness), 12, 30),
			scoreByUpper(freshness, 30),
			fmt.Sprintf("最新延迟 %d 秒", freshness),
			"衡量最新采集窗口距离当前时间的延迟，越高代表实时性越差。",
			"确认采集器在线、时间同步正常，并检查 API 与数据库之间的查询延迟。",
		),
		diagnosticLayer(
			"storage_windows",
			"窗口覆盖率",
			statusByLowerThreshold(coverage, 0.95, 0.8),
			scoreByCoverage(coverage),
			fmt.Sprintf("覆盖率 %.1f%%", coverage*100),
			"衡量查询时间范围内预期窗口和实际窗口的匹配程度，断档会降低覆盖率。",
			"排查采集器重启、ClickHouse 写入失败和 runtime 配置变更时间点。",
		),
	}

	status := "healthy"
	critical := 0
	warning := 0
	recommendations := []map[string]string{}
	for _, layer := range layers {
		layerStatus := stringValue(layer["status"])
		if statusWeight(layerStatus) > statusWeight(status) {
			status = layerStatus
		}
		if layerStatus == "critical" {
			critical++
		}
		if layerStatus == "warning" {
			warning++
		}
		if layerStatus != "healthy" {
			recommendations = append(recommendations, map[string]string{
				"level":  layerStatus,
				"title":  stringValue(layer["name"]),
				"detail": stringValue(layer["recommendation"]),
			})
		}
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, map[string]string{
			"level":  "info",
			"title":  "采集链路状态正常",
			"detail": "当前网卡计数、用户态队列、数据新鲜度和窗口覆盖率均在阈值内。",
		})
	}
	return map[string]any{
		"generated_at": now,
		"minutes":      minutes,
		"status":       status,
		"summary": map[string]any{
			"layer_count":     len(layers),
			"critical_layers": critical,
			"warning_layers":  warning,
		},
		"layers":          layers,
		"recommendations": recommendations,
	}
}

func diagnosticLayer(id, name, status string, score int, metric, detail, recommendation string) map[string]any {
	return map[string]any{
		"id":             id,
		"name":           name,
		"status":         status,
		"score":          score,
		"metric":         metric,
		"detail":         detail,
		"recommendation": recommendation,
	}
}

func statusWeight(status string) int {
	switch status {
	case "critical":
		return 3
	case "warning":
		return 2
	case "healthy":
		return 1
	default:
		return 0
	}
}

func statusByCounters(drops, errors uint64, dropRatio, errorRatio float64) string {
	if errors > 0 || errorRatio > 0 {
		return "critical"
	}
	if drops > 0 || dropRatio > 0 {
		return "warning"
	}
	return "healthy"
}

func statusByUpperThreshold(value, warning, critical float64) string {
	if value >= critical {
		return "critical"
	}
	if value >= warning {
		return "warning"
	}
	return "healthy"
}

func statusByLowerThreshold(value, warning, critical float64) string {
	if value <= 0 {
		return "unknown"
	}
	if value < critical {
		return "critical"
	}
	if value < warning {
		return "warning"
	}
	return "healthy"
}

func scoreByRatio(value float64) int {
	if value <= 0 {
		return 0
	}
	score := int(math.Round(value * 100))
	if score < 1 {
		return 1
	}
	if score > 100 {
		return 100
	}
	return score
}

func scoreByUpper(value int64, critical int64) int {
	if value <= 0 || critical <= 0 {
		return 0
	}
	score := int((value * 100) / critical)
	if score > 100 {
		return 100
	}
	return score
}

func scoreByCoverage(value float64) int {
	if value <= 0 {
		return 0
	}
	score := int(math.Round((1 - value) * 100))
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func maxCaptureSourcePressure(sources []any, field string) float64 {
	maxValue := 0.0
	for _, row := range sources {
		value := float64Value(mapValue(row)[field])
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}

func maxCaptureSourceFreshness(sources []any) int64 {
	maxValue := int64(0)
	for _, row := range sources {
		value := int64Value(mapValue(row)["freshness_seconds"])
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}

func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func sliceValue(v any) []any {
	if items, ok := v.([]any); ok {
		return items
	}
	if rows, ok := v.([]string); ok {
		items := make([]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, row)
		}
		return items
	}
	if rows, ok := v.([]map[string]any); ok {
		items := make([]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, row)
		}
		return items
	}
	if rows, ok := v.([]map[string]string); ok {
		items := make([]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, row)
		}
		return items
	}
	return []any{}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func auditActor(r *http.Request) string {
	if actor := authenticatedActor(r); actor != "" {
		return actor
	}
	actor := strings.TrimSpace(r.Header.Get("X-NexaFlow-Actor"))
	if actor == "" {
		actor = strings.TrimSpace(r.URL.Query().Get("actor"))
	}
	if actor == "" {
		actor = "operator"
	}
	return actor
}

func authenticatedActor(r *http.Request) string {
	if actor, ok := r.Context().Value(actorContextKey).(string); ok {
		return strings.TrimSpace(actor)
	}
	return ""
}

func auditClientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if comma := strings.Index(forwarded, ","); comma >= 0 {
			return strings.TrimSpace(forwarded[:comma])
		}
		return forwarded
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if colon := strings.LastIndex(remote, ":"); colon > 0 {
		return remote[:colon]
	}
	return remote
}

func filterSilencedMaps(rows []map[string]any, subjects []string, key string) []map[string]any {
	if len(subjects) == 0 {
		return rows
	}
	result := []map[string]any{}
	for _, row := range rows {
		if !isSilencedSubject(stringValue(row[key]), subjects) {
			result = append(result, row)
		}
	}
	return result
}

func isSilencedSubject(subject string, subjects []string) bool {
	for _, item := range subjects {
		if item == subject {
			return true
		}
	}
	return false
}

func removeString(items []string, target string) []string {
	result := []string{}
	for _, item := range items {
		if item != target {
			result = append(result, item)
		}
	}
	return result
}

func upsertDetectionRule(rules []model.DetectionRule, rule model.DetectionRule) []model.DetectionRule {
	next := make([]model.DetectionRule, 0, len(rules)+1)
	replaced := false
	for _, item := range rules {
		if item.ID == rule.ID {
			next = append(next, rule)
			replaced = true
			continue
		}
		next = append(next, item)
	}
	if !replaced {
		next = append(next, rule)
	}
	return next
}

func removeDetectionRule(rules []model.DetectionRule, id string) []model.DetectionRule {
	next := []model.DetectionRule{}
	for _, rule := range rules {
		if rule.ID != id {
			next = append(next, rule)
		}
	}
	return next
}

func ruleFindingIncident(row map[string]any) map[string]any {
	now := time.Now().Unix()
	if matchedAt := int64Value(row["matched_at"]); matchedAt > 0 {
		now = matchedAt
	}
	return map[string]any{
		"id":                 stringValue(row["id"]),
		"source":             "检测规则",
		"category":           stringValue(row["category"]),
		"kind":               "custom_rule",
		"severity":           stringValue(row["severity"]),
		"status":             "open",
		"subject":            stringValue(row["subject"]),
		"summary":            stringValue(row["summary"]),
		"bytes":              uint64Value(row["bytes"]),
		"packets":            uint64Value(row["packets"]),
		"score":              int64Value(row["score"]),
		"first_seen":         now,
		"last_seen":          now,
		"recommended_action": stringValue(row["recommended_action"]),
	}
}

func sortSecurityRows(rows []map[string]any) {
	sort.Slice(rows, func(i, j int) bool {
		if severityWeight(stringValue(rows[i]["severity"])) != severityWeight(stringValue(rows[j]["severity"])) {
			return severityWeight(stringValue(rows[i]["severity"])) > severityWeight(stringValue(rows[j]["severity"]))
		}
		if int64Value(rows[i]["score"]) != int64Value(rows[j]["score"]) {
			return int64Value(rows[i]["score"]) > int64Value(rows[j]["score"])
		}
		return uint64Value(rows[i]["bytes"]) > uint64Value(rows[j]["bytes"])
	})
}

func sortIncidentRows(rows []map[string]any) {
	sort.Slice(rows, func(i, j int) bool {
		if incidentStatusWeight(stringValue(rows[i]["status"])) != incidentStatusWeight(stringValue(rows[j]["status"])) {
			return incidentStatusWeight(stringValue(rows[i]["status"])) > incidentStatusWeight(stringValue(rows[j]["status"]))
		}
		if severityWeight(stringValue(rows[i]["severity"])) != severityWeight(stringValue(rows[j]["severity"])) {
			return severityWeight(stringValue(rows[i]["severity"])) > severityWeight(stringValue(rows[j]["severity"]))
		}
		if int64Value(rows[i]["score"]) != int64Value(rows[j]["score"]) {
			return int64Value(rows[i]["score"]) > int64Value(rows[j]["score"])
		}
		return int64Value(rows[i]["last_seen"]) > int64Value(rows[j]["last_seen"])
	})
}

func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 3
	case "warning", "high":
		return 2
	case "info", "medium", "low":
		return 1
	default:
		return 0
	}
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

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func int64Value(v any) int64 {
	switch value := v.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case uint64:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func float64Value(v any) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case uint:
		return float64(value)
	case uint64:
		return float64(value)
	default:
		return 0
	}
}

func boolValue(v any) bool {
	if value, ok := v.(bool); ok {
		return value
	}
	return false
}

func uint64Value(v any) uint64 {
	switch value := v.(type) {
	case uint64:
		return value
	case uint:
		return uint64(value)
	case int:
		return uint64(value)
	case int64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case float64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	default:
		return 0
	}
}

func collectorStatus(status map[string]any) string {
	latest := int64Value(status["latest_window_ts"])
	if latest == 0 || time.Now().Unix()-latest > 30 {
		return "offline"
	}
	return "online"
}

func collectorHealthAlert(collectorID string, status map[string]any) model.AlertEvent {
	if collectorStatus(status) == "online" {
		return model.AlertEvent{}
	}
	now := time.Now().Unix()
	lastSeen := int64Value(status["latest_window_ts"])
	if lastSeen == 0 {
		lastSeen = now
	}
	return model.AlertEvent{
		ID:        "collector-offline-" + collectorID,
		Severity:  "critical",
		Status:    "open",
		Subject:   collectorID,
		Summary:   "Collector 超过 30 秒未产生新采集窗口",
		FirstSeen: lastSeen,
		LastSeen:  now,
	}
}

func collectorIncident(alert model.AlertEvent) map[string]any {
	return map[string]any{
		"id":                 "alert:" + alert.ID,
		"source":             "collector",
		"category":           "采集健康",
		"kind":               "collector_offline",
		"severity":           alert.Severity,
		"status":             alert.Status,
		"subject":            alert.Subject,
		"summary":            alert.Summary,
		"bytes":              uint64(0),
		"packets":            uint64(0),
		"score":              100,
		"first_seen":         alert.FirstSeen,
		"last_seen":          alert.LastSeen,
		"recommended_action": "检查采集器容器、网卡权限和最近采集窗口写入状态",
	}
}

func alertsEmpty(alerts config.Alerts) bool {
	return alerts.FlowBytes == 0 &&
		alerts.FlowShare == 0 &&
		alerts.SourcePackets == 0 &&
		alerts.LinkUtilization == 0 &&
		len(alerts.SilencedSubjects) == 0
}
