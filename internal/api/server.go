package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	mux.HandleFunc("/api/v1/ai/incident-summary", s.aiIncidentSummary)
	mux.HandleFunc("/api/v1/ai/asset-summary", s.aiAssetSummary)
	mux.HandleFunc("/api/v1/ai/report-summary", s.aiReportSummary)
	mux.HandleFunc("/api/v1/ai/query", s.aiQuery)
	mux.HandleFunc("/api/v1/ai/incident-investigation", s.aiIncidentInvestigation)
	mux.HandleFunc("/api/v1/ai/governance-suggestions", s.aiGovernanceSuggestions)
	mux.HandleFunc("/api/v1/ai/rule-effectiveness", s.aiRuleEffectiveness)
	mux.HandleFunc("/api/v1/ai/asset-enrichment-suggestions", s.aiAssetEnrichmentSuggestions)
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
	mux.HandleFunc("/api/v1/system/audit-events", s.auditEvents)
	mux.HandleFunc("/api/v1/system/config-versions", s.configVersions)
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
	writeJSON(w, map[string]any{
		"data":     buildAIIncidentSummary(s.aiOptions(), incident, contextData),
		"degraded": incidentErr != nil || ruleErr != nil || (contextErr != nil && !aiIncidentContextUsable(contextData)),
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
	writeJSON(w, map[string]any{
		"data":     buildAIAssetSummary(s.aiOptions(), ip, findMapByString(risks, "ip", ip), profile),
		"degraded": riskErr != nil || profileErr != nil,
	})
}

func (s *Server) aiReportSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	minutes := queryMinutes(r)
	report, err := s.store.ReportOverview(r.Context(), minutes, s.aiContextLimit(queryLimit(r, 10, 50)))
	writeJSON(w, map[string]any{
		"data":     buildAIReportSummary(s.aiOptions(), report),
		"degraded": err != nil,
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
	incidents, incidentErr := s.collectSecurityIncidents(r.Context(), minutes, max(limit, 20))
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
	var timeline []map[string]any
	var timelineErr error
	if id != "" {
		timeline, timelineErr = s.store.IncidentTimeline(r.Context(), id, 20)
	}
	writeJSON(w, map[string]any{
		"data":     buildAIIncidentInvestigation(s.aiOptions(), incident, contextData, timeline),
		"degraded": incidentErr != nil || (contextErr != nil && !aiIncidentContextUsable(contextData)) || timelineErr != nil,
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
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
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

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.AuditEvents(r.Context(), queryLimit(r, 80, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
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
		"enabled":       enabled,
		"authenticated": authenticated,
		"actor":         actor,
		"role":          role,
		"can_write":     !enabled || (authenticated && role == authRoleAdmin),
	}})
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authEnabled() {
		writeJSON(w, map[string]any{"data": map[string]any{"enabled": false, "authenticated": true, "actor": "operator", "role": authRoleAdmin, "can_write": true}})
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
	role := s.loginRole(body.Password)
	if role == "" {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	actor := strings.TrimSpace(body.Actor)
	if actor == "" {
		actor = "operator"
	}
	if err := s.setAuthCookie(w, actor, role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.RecordAuditEvent(r.Context(), actor, "auth.login", "console", "控制台登录："+actor, map[string]any{"actor": actor, "role": role}, auditClientIP(r))
	writeJSON(w, map[string]any{"data": map[string]any{"enabled": true, "authenticated": true, "actor": actor, "role": role, "can_write": role == authRoleAdmin}})
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
		_ = s.store.RecordAuditEvent(r.Context(), identity.Actor, "auth.logout", "console", "控制台退出："+identity.Actor, map[string]any{"actor": identity.Actor, "role": identity.Role}, auditClientIP(r))
	}
	writeJSON(w, map[string]any{"data": map[string]any{"enabled": s.authEnabled(), "authenticated": false, "actor": "", "role": "", "can_write": false}})
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
		if requestNeedsWriteAccess(r) && identity.Role != authRoleAdmin {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), actorContextKey, identity.Actor)
		ctx = context.WithValue(ctx, roleContextKey, identity.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authEnabled() bool {
	security := s.loadSystemSettings().Security
	return security.AuthEnabled && (strings.TrimSpace(security.AdminPassword) != "" || strings.TrimSpace(security.ReadOnlyPassword) != "")
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

func requestNeedsWriteAccess(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		if r.URL.Path == "/api/v1/ai/query" {
			return false
		}
		return strings.HasPrefix(r.URL.Path, "/api/v1/")
	}
}

func normalizeAuthRole(role string) string {
	switch strings.TrimSpace(role) {
	case authRoleViewer:
		return authRoleViewer
	default:
		return authRoleAdmin
	}
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
	_ = s.store.RecordAuditEvent(r.Context(), auditActor(r), action, target, summary, detail, auditClientIP(r))
}

func (s *Server) configSnapshot(r *http.Request, scope, target, action, summary string, snapshot any) {
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

type aiQueryIntent struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	API         string         `json:"api"`
	Question    string         `json:"question"`
	Minutes     int            `json:"minutes"`
	Limit       int            `json:"limit"`
	Params      map[string]any `json:"params"`
}

type aiSummaryOptions struct {
	Enabled  bool
	Mode     string
	Provider string
	Model    string
}

func parseAIQueryIntent(question string, minutes, limit int) aiQueryIntent {
	normalized := strings.ToLower(strings.TrimSpace(question))
	ip := firstIPv4(question)
	base := aiQueryIntent{
		ID:       "top_src",
		Title:    "源 IP 流量排行",
		API:      "/api/v1/traffic/topn",
		Question: question,
		Minutes:  minutes,
		Limit:    limit,
		Params:   map[string]any{"dimension": "ip", "direction": "src"},
	}
	switch {
	case ip != "" && containsAny(normalized, "连接", "访问", "会话", "外联", "通信"):
		base.ID = "sessions_for_ip"
		base.Title = "资产会话追踪"
		base.API = "/api/v1/traffic/sessions"
		base.Params = map[string]any{"q": ip}
	case ip != "" && containsAny(normalized, "画像", "资产", "风险", "解释"):
		base.ID = "asset_profile"
		base.Title = "资产画像"
		base.API = "/api/v1/traffic/ip-profile"
		base.Params = map[string]any{"ip": ip}
	case containsAny(normalized, "公网", "外部", "外联", "互联网", "暴露"):
		base.ID = "external_access"
		base.Title = "公网访问分析"
		base.API = "/api/v1/traffic/external-access"
		base.Params = map[string]any{}
	case containsAny(normalized, "事件", "告警", "风险事件"):
		base.ID = "incidents"
		base.Title = "安全事件分析"
		base.API = "/api/v1/security/incidents"
		base.Params = map[string]any{}
	case containsAny(normalized, "严重资产", "资产风险", "高风险资产"):
		base.ID = "asset_risk"
		base.Title = "资产风险排行"
		base.API = "/api/v1/assets/risk-posture"
		base.Params = map[string]any{}
	case containsAny(normalized, "异常", "波动", "突增", "新增"):
		base.ID = "anomalies"
		base.Title = "异常波动分析"
		base.API = "/api/v1/traffic/anomalies"
		base.Params = map[string]any{}
	case containsAny(normalized, "服务", "应用"):
		base.ID = "top_services"
		base.Title = "应用服务排行"
		base.API = "/api/v1/traffic/topn"
		base.Params = map[string]any{"dimension": "service", "direction": "src"}
	case containsAny(normalized, "端口"):
		base.ID = "top_ports"
		base.Title = "目的端口排行"
		base.API = "/api/v1/traffic/topn"
		base.Params = map[string]any{"dimension": "dst_port", "direction": "src"}
	case containsAny(normalized, "目的ip", "目的 ip", "被访问", "访问最多"):
		base.ID = "top_dst"
		base.Title = "目的 IP 流量排行"
		base.API = "/api/v1/traffic/topn"
		base.Params = map[string]any{"dimension": "ip", "direction": "dst"}
	}
	base.Description = aiIntentDescription(base.ID)
	return base
}

func (s *Server) runAIQuery(ctx context.Context, intent aiQueryIntent) (map[string]any, error) {
	var rows []map[string]any
	var err error
	switch intent.ID {
	case "sessions_for_ip":
		rows, err = s.store.Sessions(ctx, stringValue(intent.Params["q"]), intent.Minutes, intent.Limit)
	case "asset_profile":
		var profile map[string]any
		profile, err = s.store.IPProfile(ctx, stringValue(intent.Params["ip"]), intent.Minutes)
		rows = aiProfileRows(profile)
	case "external_access":
		rows, err = s.store.ExternalAccess(ctx, intent.Minutes, intent.Limit)
	case "incidents":
		rows, err = s.collectSecurityIncidents(ctx, intent.Minutes, intent.Limit)
	case "asset_risk":
		rows, err = s.store.AssetRiskPosture(ctx, intent.Minutes, intent.Limit)
	case "anomalies":
		rows, err = s.store.TrafficAnomalies(ctx, intent.Minutes, intent.Limit)
	case "top_services":
		var items []model.TopItem
		items, err = s.store.TopN(ctx, "service", "src", intent.Limit, intent.Minutes)
		rows = topItemsToAIRows(items, "service")
	case "top_ports":
		var items []model.TopItem
		items, err = s.store.TopN(ctx, "dst_port", "src", intent.Limit, intent.Minutes)
		rows = topItemsToAIRows(items, "dst_port")
	case "top_dst":
		var items []model.TopItem
		items, err = s.store.TopN(ctx, "ip", "dst", intent.Limit, intent.Minutes)
		rows = topItemsToAIRows(items, "dst_ip")
	default:
		var items []model.TopItem
		items, err = s.store.TopN(ctx, "ip", "src", intent.Limit, intent.Minutes)
		rows = topItemsToAIRows(items, "src_ip")
	}
	return buildAIQueryResponse(s.aiOptions(), intent, rows), err
}

func buildAIQueryResponse(options aiSummaryOptions, intent aiQueryIntent, rows []map[string]any) map[string]any {
	findings := aiQueryFindings(intent, rows)
	evidence := aiQueryEvidence(intent, rows)
	actions := aiQueryActions(intent, rows)
	summary := fmt.Sprintf("已将问题归类为「%s」，在最近 %d 分钟内检索到 %d 条相关结果。", intent.Title, intent.Minutes, len(rows))
	if len(findings) > 0 {
		summary = findings[0]
	}
	return map[string]any{
		"enabled":      options.Enabled,
		"mode":         options.Mode,
		"provider":     options.Provider,
		"model":        options.Model,
		"question":     intent.Question,
		"intent":       intent,
		"title":        "AI 查询结果",
		"summary":      summary,
		"confidence":   confidenceByContext(len(rows)),
		"findings":     findings,
		"evidence":     evidence,
		"actions":      actions,
		"rows":         rows,
		"followups":    aiQueryFollowups(intent),
		"generated_at": time.Now().Unix(),
	}
}

func buildAIIncidentInvestigation(options aiSummaryOptions, incident, contextData map[string]any, timeline []map[string]any) map[string]any {
	if timeline == nil {
		timeline = []map[string]any{}
	}
	summary := buildAIIncidentSummary(options, incident, contextData)
	subject := firstString(stringValue(summary["subject"]), stringValue(contextData["subject"]), "未知事件对象")
	sessions := sliceValue(contextData["sessions"])
	insights := sliceValue(contextData["insights"])
	anomalies := sliceValue(contextData["anomalies"])
	rootCauses := []string{"业务流量峰值或计划内变更", "公网扫描、异常外联或服务暴露扩大", "采集质量异常导致指标失真"}
	if len(insights) > 0 {
		rootCauses = append([]string{"规则或风险线索命中，优先核对命中对象是否符合业务白名单"}, rootCauses...)
	}
	if len(anomalies) > 0 {
		rootCauses = append([]string{"历史基线偏离或新增对象出现，优先确认是否存在变更窗口"}, rootCauses...)
	}
	evidenceChain := []string{
		fmt.Sprintf("事件对象：%s", subject),
		fmt.Sprintf("关联会话：%d 条", len(sessions)),
		fmt.Sprintf("风险线索：%d 条", len(insights)),
		fmt.Sprintf("异常波动：%d 条", len(anomalies)),
		fmt.Sprintf("处置时间线：%d 条", len(timeline)),
	}
	nextSteps := []string{
		"先查看首要关联会话，确认源、目的、端口和服务用途。",
		"核对资产负责人、业务标签、暴露策略和白名单记录。",
		"若确认为异常，补充事件备注并沉淀检测规则或临时静默策略。",
	}
	return map[string]any{
		"enabled":        options.Enabled,
		"mode":           options.Mode,
		"provider":       options.Provider,
		"model":          options.Model,
		"subject":        subject,
		"summary":        summary,
		"root_causes":    rootCauses,
		"evidence_chain": evidenceChain,
		"next_steps":     nextSteps,
		"context":        contextData,
		"timeline":       timeline,
		"generated_at":   time.Now().Unix(),
	}
}

func buildAIGovernanceSuggestions(options aiSummaryOptions, report map[string]any, alerts config.Alerts, minutes, limit int) map[string]any {
	suggestions := []map[string]any{}
	incidents := sliceValue(report["incidents"])
	anomalies := sliceValue(report["anomalies"])
	exposures := sliceValue(report["exposures"])
	externalRows := sliceValue(report["external_access"])
	assetRisks := sliceValue(report["asset_risks"])

	if len(incidents) > 0 {
		incident := mapValue(incidents[0])
		subject := stringValue(incident["subject"])
		suggestions = append(suggestions, governanceSuggestion(
			"rule", firstString(stringValue(incident["severity"]), "warning"),
			"沉淀首要事件检测规则", subject,
			"首要事件反复出现时，建议把当前事件对象沉淀为检测规则草案，便于后续自动识别。",
			confidenceByContext(len(incidents)),
			[]string{
				"事件摘要：" + firstString(stringValue(incident["summary"]), "-"),
				"事件级别：" + aiSeverityText(firstString(stringValue(incident["severity"]), "warning")),
				"事件流量：" + formatAIBytes(uint64Value(incident["bytes"])),
			},
			[]string{"确认事件是否为真实风险。", "如确认有效，将草案填入规则中心后再人工保存。"},
			proposedRule("AI 推荐：首要事件 "+shortTarget(subject), "事件检测", ruleMetricForIncident(incident), subject, thresholdForIncident(incident), firstString(stringValue(incident["severity"]), "warning"), firstString(stringValue(incident["recommended_action"]), "核对事件对象、关联会话和资产归属。")),
			nil,
		))
	}
	if len(externalRows) > 0 {
		row := mapValue(externalRows[0])
		target := firstString(stringValue(row["public_ip"]), "-") + " -> " + firstString(stringValue(row["internal_ip"]), "-") + ":" + firstString(stringValue(row["port"]), "-")
		if !isSilencedSubject(target, alerts.SilencedSubjects) {
			suggestions = append(suggestions, governanceSuggestion(
				"whitelist_review", riskSeverity(stringValue(row["risk"])),
				"公网访问白名单复核", target,
				"该公网访问对象有稳定业务可能，但仍需管理员确认来源、端口和资产归属后再决定是否加入白名单。",
				confidenceByContext(int(int64Value(row["session_count"]))),
				[]string{
					"公网来源：" + firstString(stringValue(row["public_ip"]), "-"),
					"内部资产：" + firstString(stringValue(row["internal_ip"]), "-"),
					"服务端口：" + firstString(stringValue(row["port"]), "-") + " / " + firstString(stringValue(row["service"]), "-"),
					"会话数量：" + strconv.FormatInt(int64Value(row["session_count"]), 10),
				},
				[]string{"确认访问方是否可信。", "确认服务用途和防火墙策略。", "只有长期稳定且低风险的业务流量才建议加入白名单。"},
				nil,
				map[string]any{"subject": target, "reason": "AI 推荐复核公网访问白名单", "scope": "external_access"},
			))
		}
	}
	if len(exposures) > 0 {
		row := mapValue(exposures[0])
		target := firstString(stringValue(row["ip"]), "-") + ":" + firstString(stringValue(row["port"]), "-")
		suggestions = append(suggestions, governanceSuggestion(
			"rule", riskSeverity(stringValue(row["risk"])),
			"暴露服务客户端数规则", target,
			"该服务暴露面可用客户端数量做检测条件，适合识别来源扩散或暴露范围扩大。",
			confidenceByContext(int(int64Value(row["client_count"]))),
			[]string{
				"暴露服务：" + target + " / " + firstString(stringValue(row["service"]), "-"),
				"客户端数量：" + strconv.FormatInt(int64Value(row["client_count"]), 10),
				"风险等级：" + assetRiskLevelText(stringValue(row["risk"])),
			},
			[]string{"确认端口是否应对公网或跨网段开放。", "如来源扩散不符合预期，将草案保存为检测规则。"},
			proposedRule("AI 推荐：暴露服务 "+target, "服务暴露", "exposed_clients", target, maxFloat(float64(int64Value(row["client_count"])), 5), riskSeverity(stringValue(row["risk"])), "核对服务暴露来源、客户端数量和访问策略。"),
			nil,
		))
	}
	if len(anomalies) > 0 {
		row := mapValue(anomalies[0])
		dimension := stringValue(row["dimension"])
		target := firstString(stringValue(row["key"]), "-")
		suggestions = append(suggestions, governanceSuggestion(
			"rule", firstString(stringValue(row["severity"]), "warning"),
			"异常波动检测规则", target,
			"该对象偏离历史窗口，建议用当前维度和流量规模生成检测规则草案。",
			confidenceByContext(len(anomalies)),
			[]string{
				"异常摘要：" + firstString(stringValue(row["summary"]), "-"),
				"当前流量：" + formatAIBytes(uint64Value(row["current_bytes"])),
				"变化比例：" + fmt.Sprintf("%.2f", float64Value(row["change_ratio"])),
			},
			[]string{"确认是否处于变更窗口。", "对非计划新增或突增对象沉淀检测规则。"},
			proposedRule("AI 推荐：异常波动 "+shortTarget(target), "行为基线", ruleMetricForDimension(dimension), target, maxFloat(float64(uint64Value(row["current_bytes"]))*0.8, 1), firstString(stringValue(row["severity"]), "warning"), "确认异常对象是否符合业务预期，必要时下钻会话和资产画像。"),
			nil,
		))
	}
	if len(assetRisks) > 0 {
		row := mapValue(assetRisks[0])
		ip := firstString(stringValue(row["ip"]), "-")
		suggestions = append(suggestions, governanceSuggestion(
			"asset_governance", firstString(stringValue(row["risk_level"]), "warning"),
			"补齐高风险资产归属", ip,
			"高风险资产需要优先补齐负责人、业务系统、环境和重要性，后续事件才能稳定分派和复盘。",
			confidenceByContext(int(int64Value(row["open_incidents"])+int64Value(row["exposed_services"])+int64Value(row["external_peers"]))),
			[]string{
				"风险评分：" + strconv.FormatInt(int64Value(row["risk_score"]), 10),
				"开放事件：" + strconv.FormatInt(int64Value(row["open_incidents"]), 10),
				"暴露服务：" + strconv.FormatInt(int64Value(row["exposed_services"]), 10),
				"主要原因：" + firstString(stringValue(row["top_finding"]), "-"),
			},
			[]string{"进入资产风险页核对该资产。", "补齐负责人、业务标签、环境和重要性。", "处理该资产关联开放事件。"},
			nil,
			nil,
		))
	}
	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}
	return map[string]any{
		"enabled":      options.Enabled,
		"mode":         options.Mode,
		"provider":     options.Provider,
		"model":        options.Model,
		"minutes":      minutes,
		"summary":      fmt.Sprintf("基于最近 %d 分钟数据生成 %d 条治理建议，所有建议均需管理员人工确认后执行。", minutes, len(suggestions)),
		"suggestions":  suggestions,
		"generated_at": time.Now().Unix(),
	}
}

func buildAIRuleEffectiveness(options aiSummaryOptions, rules []model.DetectionRule, findings []map[string]any, alerts config.Alerts, minutes int) map[string]any {
	rows := make([]map[string]any, 0, len(rules))
	tuning := []map[string]any{}
	totalHits := 0
	criticalHits := 0
	noisyRules := 0
	quietRules := 0
	disabledRules := 0
	for _, rule := range rules {
		ruleFindings := findingsForRule(findings, rule)
		row := buildAIRuleEffectivenessRow(rule, ruleFindings, alerts, minutes)
		rows = append(rows, row)
		hits := int(int64Value(row["hit_count"]))
		totalHits += hits
		criticalHits += int(int64Value(row["critical_count"]))
		switch stringValue(row["noise_level"]) {
		case "noisy":
			noisyRules++
		case "quiet":
			quietRules++
		}
		if !rule.Enabled {
			disabledRules++
		}
		tuning = append(tuning, ruleTuningSuggestions(row)...)
	}
	sort.Slice(rows, func(i, j int) bool {
		return float64Value(rows[i]["score"]) > float64Value(rows[j]["score"])
	})
	summary := map[string]any{
		"minutes":        minutes,
		"rule_count":     len(rules),
		"enabled_rules":  len(rules) - disabledRules,
		"disabled_rules": disabledRules,
		"total_hits":     totalHits,
		"critical_hits":  criticalHits,
		"noisy_rules":    noisyRules,
		"quiet_rules":    quietRules,
		"health":         ruleHealthText(len(rules), totalHits, noisyRules, quietRules),
	}
	return map[string]any{
		"enabled":            options.Enabled,
		"mode":               options.Mode,
		"provider":           options.Provider,
		"model":              options.Model,
		"summary":            summary,
		"rules":              rows,
		"tuning_suggestions": tuning,
		"generated_at":       time.Now().Unix(),
	}
}

func buildAIAssetEnrichmentSuggestions(options aiSummaryOptions, risks []map[string]any, minutes, limit int) map[string]any {
	suggestions := []map[string]any{}
	for _, risk := range risks {
		if len(suggestions) >= limit {
			break
		}
		ip := stringValue(risk["ip"])
		if ip == "" {
			continue
		}
		missing := assetMissingFields(risk)
		if len(missing) == 0 && int64Value(risk["risk_score"]) < 70 {
			continue
		}
		suggestions = append(suggestions, assetEnrichmentSuggestion(options, risk, missing))
	}
	return map[string]any{
		"enabled":      options.Enabled,
		"mode":         options.Mode,
		"provider":     options.Provider,
		"model":        options.Model,
		"minutes":      minutes,
		"summary":      fmt.Sprintf("基于最近 %d 分钟资产风险、暴露服务和公网访问生成 %d 条资产画像补全建议。", minutes, len(suggestions)),
		"suggestions":  suggestions,
		"generated_at": time.Now().Unix(),
	}
}

func assetEnrichmentSuggestion(options aiSummaryOptions, risk map[string]any, missing []string) map[string]any {
	ip := stringValue(risk["ip"])
	riskLevel := firstString(stringValue(risk["risk_level"]), "info")
	metadata := proposedAssetMetadata(risk)
	evidence := []string{
		"风险评分：" + strconv.FormatInt(int64Value(risk["risk_score"]), 10),
		"风险等级：" + assetRiskLevelText(riskLevel),
		"公网对端：" + strconv.FormatInt(int64Value(risk["external_peers"]), 10),
		"暴露服务：" + strconv.FormatInt(int64Value(risk["exposed_services"]), 10),
		"开放事件：" + strconv.FormatInt(int64Value(risk["open_incidents"]), 10),
		"主要原因：" + firstString(stringValue(risk["top_finding"]), "-"),
	}
	actions := []string{"确认资产负责人和业务系统。", "复核推荐标签是否符合实际用途。", "填入资产台账后再保存。"}
	if int64Value(risk["open_incidents"]) > 0 {
		actions = append([]string{"先处理该资产关联开放事件。"}, actions...)
	}
	return map[string]any{
		"id":                "ai:asset-enrichment:" + ip,
		"type":              "asset_enrichment",
		"severity":          riskSeverity(riskLevel),
		"ip":                ip,
		"title":             "补全资产画像：" + ip,
		"summary":           assetEnrichmentSummary(risk, missing),
		"confidence":        confidenceByContext(len(missing) + int(int64Value(risk["open_incidents"])) + int(int64Value(risk["exposed_services"])) + int(int64Value(risk["external_peers"]))),
		"missing_fields":    missing,
		"evidence":          evidence,
		"actions":           actions,
		"proposed_metadata": metadata,
		"generated_at":      time.Now().Unix(),
		"enabled":           options.Enabled,
	}
}

func proposedAssetMetadata(risk map[string]any) map[string]any {
	ip := stringValue(risk["ip"])
	tags := mergeTags(sliceValue(risk["tags"]), inferredAssetTags(risk))
	name := firstString(stringValue(risk["name"]), inferredAssetName(risk))
	owner := firstString(stringValue(risk["owner"]), "待分配")
	business := firstString(stringValue(risk["business"]), inferredAssetBusiness(risk))
	environment := stringValue(risk["environment"])
	if environment == "" || environment == "未分类" {
		environment = inferredAssetEnvironment(risk)
	}
	criticality := stringValue(risk["criticality"])
	if criticality == "" || (criticality == "normal" && int64Value(risk["risk_score"]) >= 70) {
		criticality = inferredAssetCriticality(risk)
	}
	note := strings.TrimSpace(stringValue(risk["note"]))
	inferredNote := fmt.Sprintf("AI 建议补全：风险评分 %d，%s。", int64Value(risk["risk_score"]), firstString(stringValue(risk["top_finding"]), "近期活跃资产"))
	if note == "" {
		note = inferredNote
	}
	return map[string]any{
		"ip":          ip,
		"name":        name,
		"owner":       owner,
		"business":    business,
		"environment": environment,
		"criticality": criticality,
		"tags":        tags,
		"note":        note,
	}
}

func assetMissingFields(risk map[string]any) []string {
	fields := []struct {
		key   string
		label string
	}{
		{"name", "资产名称"},
		{"owner", "负责人"},
		{"business", "业务系统"},
		{"environment", "环境"},
		{"criticality", "重要性"},
	}
	missing := []string{}
	for _, field := range fields {
		value := strings.TrimSpace(stringValue(risk[field.key]))
		if value == "" || value == "未分类" || value == "normal" && field.key == "criticality" && int64Value(risk["risk_score"]) >= 70 {
			missing = append(missing, field.label)
		}
	}
	return missing
}

func assetEnrichmentSummary(risk map[string]any, missing []string) string {
	ip := stringValue(risk["ip"])
	if len(missing) > 0 {
		return fmt.Sprintf("%s 缺少 %s，且当前风险等级为 %s，建议优先补齐画像。", ip, strings.Join(missing, "、"), assetRiskLevelText(stringValue(risk["risk_level"])))
	}
	return fmt.Sprintf("%s 当前风险较高，建议复核已有资产画像并补充处置备注。", ip)
}

func inferredAssetName(risk map[string]any) string {
	ip := stringValue(risk["ip"])
	switch {
	case int64Value(risk["exposed_services"]) > 0:
		return "公网服务资产 " + ip
	case int64Value(risk["external_sessions"]) > 0:
		return "外联活跃资产 " + ip
	default:
		return "活跃资产 " + ip
	}
}

func inferredAssetBusiness(risk map[string]any) string {
	switch {
	case int64Value(risk["exposed_services"]) > 0:
		return "公网服务"
	case int64Value(risk["external_sessions"]) > 0:
		return "外联业务"
	case uint64Value(risk["total_bytes"]) > 1024*1024*1024:
		return "高流量业务"
	default:
		return "待确认业务"
	}
}

func inferredAssetEnvironment(risk map[string]any) string {
	if int64Value(risk["risk_score"]) >= 70 || int64Value(risk["exposed_services"]) > 0 {
		return "生产"
	}
	return "未分类"
}

func inferredAssetCriticality(risk map[string]any) string {
	switch {
	case int64Value(risk["risk_score"]) >= 80 || int64Value(risk["critical_incidents"]) > 0:
		return "critical"
	case int64Value(risk["risk_score"]) >= 55 || int64Value(risk["exposed_services"]) > 0:
		return "high"
	default:
		return "normal"
	}
}

func inferredAssetTags(risk map[string]any) []string {
	tags := []string{"AI建议"}
	if role := stringValue(risk["role"]); role != "" {
		tags = append(tags, role)
	}
	if int64Value(risk["external_peers"]) > 0 || int64Value(risk["external_sessions"]) > 0 {
		tags = append(tags, "公网访问")
	}
	if int64Value(risk["exposed_services"]) > 0 {
		tags = append(tags, "服务暴露")
	}
	if int64Value(risk["open_incidents"]) > 0 {
		tags = append(tags, "开放事件")
	}
	if int64Value(risk["risk_score"]) >= 70 {
		tags = append(tags, "高风险")
	}
	return tags
}

func mergeTags(raw []any, inferred []string) []string {
	seen := map[string]bool{}
	tags := []string{}
	for _, value := range raw {
		tag := strings.TrimSpace(stringValue(value))
		if tag != "" && !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	for _, tag := range inferred {
		tag = strings.TrimSpace(tag)
		if tag != "" && !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	return tags
}

func buildAIRuleEffectivenessRow(rule model.DetectionRule, findings []map[string]any, alerts config.Alerts, minutes int) map[string]any {
	subjects := map[string]int{}
	criticalCount := 0
	warningCount := 0
	silencedCount := 0
	totalBytes := uint64(0)
	peakValue := 0.0
	topSubject := ""
	for _, finding := range findings {
		subject := stringValue(finding["subject"])
		if subject == "" {
			subject = stringValue(finding["id"])
		}
		subjects[subject]++
		if subjects[subject] == 1 && topSubject == "" {
			topSubject = subject
		}
		switch stringValue(finding["severity"]) {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		}
		if isSilencedSubject(subject, alerts.SilencedSubjects) {
			silencedCount++
		}
		totalBytes += uint64Value(finding["bytes"])
		peakValue = maxFloat(peakValue, float64Value(finding["value"]))
	}
	hitCount := len(findings)
	uniqueSubjects := len(subjects)
	duplicateRatio := 0.0
	if hitCount > 0 {
		duplicateRatio = 1 - float64(uniqueSubjects)/float64(hitCount)
	}
	noiseLevel := ruleNoiseLevel(rule.Enabled, hitCount, uniqueSubjects, criticalCount, duplicateRatio)
	score := ruleEffectivenessScore(rule.Enabled, hitCount, uniqueSubjects, criticalCount, duplicateRatio, silencedCount)
	return map[string]any{
		"id":              rule.ID,
		"name":            rule.Name,
		"category":        rule.Category,
		"metric":          rule.Metric,
		"match":           rule.Match,
		"operator":        rule.Operator,
		"threshold":       rule.Threshold,
		"severity":        rule.Severity,
		"enabled_rule":    rule.Enabled,
		"minutes":         minutes,
		"hit_count":       hitCount,
		"critical_count":  criticalCount,
		"warning_count":   warningCount,
		"unique_subjects": uniqueSubjects,
		"duplicate_ratio": duplicateRatio,
		"silenced_hits":   silencedCount,
		"total_bytes":     totalBytes,
		"peak_value":      peakValue,
		"top_subject":     topSubject,
		"noise_level":     noiseLevel,
		"score":           score,
		"summary":         ruleEffectivenessSummary(rule, hitCount, uniqueSubjects, criticalCount, duplicateRatio, noiseLevel),
		"recommendations": ruleEffectivenessActions(rule, hitCount, uniqueSubjects, criticalCount, duplicateRatio, silencedCount, noiseLevel),
		"sample_findings": findings[:min(len(findings), 3)],
		"generated_at":    time.Now().Unix(),
	}
}

func findingsForRule(findings []map[string]any, rule model.DetectionRule) []map[string]any {
	rows := []map[string]any{}
	for _, finding := range findings {
		if stringValue(finding["rule_id"]) == rule.ID || stringValue(finding["rule_name"]) == rule.Name {
			rows = append(rows, finding)
		}
	}
	return rows
}

func ruleNoiseLevel(enabled bool, hits, uniqueSubjects, criticalCount int, duplicateRatio float64) string {
	switch {
	case !enabled:
		return "disabled"
	case hits == 0:
		return "quiet"
	case duplicateRatio >= 0.65 && hits >= 8:
		return "noisy"
	case hits >= 30 && criticalCount == 0:
		return "noisy"
	case criticalCount > 0:
		return "critical"
	case uniqueSubjects <= 3 && hits <= 10:
		return "focused"
	default:
		return "active"
	}
}

func ruleEffectivenessScore(enabled bool, hits, uniqueSubjects, criticalCount int, duplicateRatio float64, silencedCount int) int {
	if !enabled {
		return 20
	}
	score := 55
	if hits == 0 {
		score = 45
	}
	if hits > 0 {
		score += min(hits*2, 20)
	}
	if criticalCount > 0 {
		score += min(criticalCount*6, 18)
	}
	if uniqueSubjects > 0 && uniqueSubjects <= 5 {
		score += 8
	}
	if duplicateRatio >= 0.65 {
		score -= 20
	}
	if silencedCount > 0 {
		score -= min(silencedCount*3, 18)
	}
	return max(0, min(score, 100))
}

func ruleEffectivenessSummary(rule model.DetectionRule, hits, uniqueSubjects, criticalCount int, duplicateRatio float64, noiseLevel string) string {
	if !rule.Enabled {
		return "规则当前未启用，不参与实时检测。"
	}
	if hits == 0 {
		return "规则在当前观察窗口内没有命中，需要结合业务预期判断是否过严或场景暂未出现。"
	}
	if noiseLevel == "noisy" {
		return fmt.Sprintf("规则命中 %d 次，唯一对象 %d 个，重复率 %.0f%%，存在告警噪声风险。", hits, uniqueSubjects, duplicateRatio*100)
	}
	if criticalCount > 0 {
		return fmt.Sprintf("规则命中 %d 次，其中严重命中 %d 次，建议优先复核首要对象。", hits, criticalCount)
	}
	return fmt.Sprintf("规则命中 %d 次，覆盖 %d 个对象，当前处于可观察状态。", hits, uniqueSubjects)
}

func ruleEffectivenessActions(rule model.DetectionRule, hits, uniqueSubjects, criticalCount int, duplicateRatio float64, silencedCount int, noiseLevel string) []string {
	switch noiseLevel {
	case "disabled":
		return []string{"确认该规则是否仍需要保留；如属于核心检测场景，启用前先复核阈值和匹配对象。"}
	case "quiet":
		return []string{"保持观察或扩大时间窗口；如果长期无命中，评估是否降低阈值或删除无效规则。"}
	case "noisy":
		return []string{"提高阈值或收窄匹配对象。", "对重复命中的稳定业务流量先做白名单复核。", "检查规则说明和处置动作是否足够明确。"}
	case "critical":
		return []string{"优先查看严重命中的对象画像和事件上下文。", "确认是否需要生成事件备注或升级处置。"}
	default:
		actions := []string{"保持规则启用，并定期复核命中对象和误报情况。"}
		if silencedCount > 0 {
			actions = append(actions, "当前存在静默命中，建议审计白名单是否仍有效。")
		}
		if duplicateRatio > 0.35 && hits > uniqueSubjects {
			actions = append(actions, "重复命中偏高，可考虑按对象聚合事件或调高阈值。")
		}
		if criticalCount == 0 && rule.Severity == "critical" {
			actions = append(actions, "规则级别为严重但当前无严重命中，建议复核级别设置。")
		}
		return actions
	}
}

func ruleTuningSuggestions(row map[string]any) []map[string]any {
	noiseLevel := stringValue(row["noise_level"])
	if noiseLevel == "" || noiseLevel == "active" || noiseLevel == "focused" {
		return []map[string]any{}
	}
	title := "复核规则：" + firstString(stringValue(row["name"]), stringValue(row["id"]), "-")
	suggestion := map[string]any{
		"rule_id":     stringValue(row["id"]),
		"rule_name":   stringValue(row["name"]),
		"noise_level": noiseLevel,
		"severity":    firstString(stringValue(row["severity"]), "info"),
		"title":       title,
		"summary":     stringValue(row["summary"]),
		"actions":     sliceValue(row["recommendations"]),
		"score":       int64Value(row["score"]),
	}
	return []map[string]any{suggestion}
}

func ruleHealthText(ruleCount, totalHits, noisyRules, quietRules int) string {
	switch {
	case ruleCount == 0:
		return "未配置检测规则"
	case noisyRules > 0:
		return "存在噪声规则"
	case totalHits == 0:
		return "规则静默观察"
	case quietRules == ruleCount:
		return "整体偏静默"
	default:
		return "规则运行正常"
	}
}

func governanceSuggestion(kind, severity, title, target, summary string, confidence float64, evidence, actions []string, rule, silence map[string]any) map[string]any {
	idParts := []string{"ai", kind, severity, target}
	item := map[string]any{
		"id":         strings.ToLower(strings.ReplaceAll(strings.Join(idParts, ":"), " ", "-")),
		"type":       kind,
		"severity":   firstString(severity, "info"),
		"title":      title,
		"target":     target,
		"summary":    summary,
		"confidence": confidence,
		"evidence":   evidence,
		"actions":    actions,
	}
	if rule != nil {
		item["proposed_rule"] = rule
	}
	if silence != nil {
		item["proposed_silence"] = silence
	}
	return item
}

func proposedRule(name, category, metric, match string, threshold float64, severity, action string) map[string]any {
	return map[string]any{
		"id":                 "",
		"name":               name,
		"category":           category,
		"metric":             metric,
		"match":              match,
		"operator":           "gte",
		"threshold":          math.Ceil(threshold),
		"severity":           firstString(riskSeverity(severity), "warning"),
		"enabled":            true,
		"description":        "由 AI 治理建议生成的规则草案，保存前请人工确认阈值、匹配对象和级别。",
		"recommended_action": action,
		"updated_at":         time.Now().Unix(),
	}
}

func ruleMetricForIncident(incident map[string]any) string {
	kind := strings.ToLower(stringValue(incident["kind"]))
	subject := strings.ToLower(stringValue(incident["subject"]))
	switch {
	case strings.Contains(kind, "external") || strings.Contains(subject, "->"):
		return "external_sessions"
	case strings.Contains(subject, "dst_port:"):
		return "dst_port_bytes"
	case strings.Contains(subject, "service:"):
		return "service_bytes"
	default:
		return "flow_bytes"
	}
}

func thresholdForIncident(incident map[string]any) float64 {
	if value := float64Value(incident["value"]); value > 0 {
		return value
	}
	if ruleMetricForIncident(incident) == "external_sessions" {
		return 1
	}
	if packets := uint64Value(incident["packets"]); packets > 0 {
		return float64(packets)
	}
	if bytes := uint64Value(incident["bytes"]); bytes > 0 {
		return float64(bytes) * 0.8
	}
	return 1
}

func ruleMetricForDimension(dimension string) string {
	switch strings.ToLower(strings.TrimSpace(dimension)) {
	case "src_ip", "source_ip", "ip":
		return "src_ip_bytes"
	case "dst_ip":
		return "dst_ip_bytes"
	case "dst_port", "port":
		return "dst_port_bytes"
	case "service":
		return "service_bytes"
	case "flow":
		return "flow_bytes"
	default:
		return "flow_bytes"
	}
}

func riskSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "严重":
		return "critical"
	case "high", "warning", "medium", "警告":
		return "warning"
	default:
		return "info"
	}
}

func shortTarget(target string) string {
	target = strings.TrimSpace(target)
	if len(target) <= 28 {
		return target
	}
	return target[:28]
}

func (s *Server) collectSecurityIncidents(ctx context.Context, minutes, limit int) ([]map[string]any, error) {
	incidents, incidentErr := s.store.SecurityIncidents(ctx, minutes, limit)
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	ruleRows, ruleErr := s.store.DetectionRuleFindings(ctx, runtime.Alerts.DetectionRules, minutes, limit)
	for _, row := range ruleRows {
		incidents = append(incidents, ruleFindingIncident(row))
	}
	incidents = filterSilencedMaps(incidents, runtime.Alerts.SilencedSubjects, "subject")
	sortIncidentRows(incidents)
	if incidentErr != nil {
		return incidents, incidentErr
	}
	return incidents, ruleErr
}

func aiQueryFindings(intent aiQueryIntent, rows []map[string]any) []string {
	if len(rows) == 0 {
		return []string{"当前窗口没有检索到匹配数据，建议扩大时间范围或换一个对象继续查询。"}
	}
	top := rows[0]
	key := firstString(stringValue(top["key"]), stringValue(top["ip"]), stringValue(top["subject"]), stringValue(top["public_ip"]), stringValue(top["service"]), stringValue(top["src_ip"]), "-")
	bytes := uint64Value(top["bytes"])
	findings := []string{fmt.Sprintf("%s 的首要对象是 %s，流量约 %s。", intent.Title, key, formatAIBytes(bytes))}
	if packets := uint64Value(top["packets"]); packets > 0 {
		findings = append(findings, fmt.Sprintf("首要对象关联包数约 %d，建议结合会话和端口继续下钻。", packets))
	}
	if severity := stringValue(top["severity"]); severity != "" {
		findings = append(findings, "首要对象级别为 "+aiSeverityText(severity)+"。")
	}
	if risk := firstString(stringValue(top["risk_level"]), stringValue(top["risk"])); risk != "" {
		findings = append(findings, "首要对象风险标记为 "+assetRiskLevelText(risk)+"。")
	}
	return findings
}

func aiQueryEvidence(intent aiQueryIntent, rows []map[string]any) []string {
	evidence := []string{
		"查询意图：" + intent.Title,
		"调用接口：" + intent.API,
		"观察窗口：" + strconv.Itoa(intent.Minutes) + " 分钟",
		"结果数量：" + strconv.Itoa(len(rows)),
	}
	if len(rows) > 0 {
		evidence = append(evidence, "首要结果："+configValueText(rows[0]))
	}
	return evidence
}

func aiQueryActions(intent aiQueryIntent, rows []map[string]any) []string {
	actions := []string{"查看结果表中的首要对象，再进入对应画像、会话或事件上下文下钻。"}
	switch intent.ID {
	case "external_access":
		actions = append(actions, "核对公网来源和内部资产暴露端口，确认是否属于业务白名单。")
	case "incidents", "anomalies":
		actions = append(actions, "优先处理严重级别对象，并补充事件备注保留处置结论。")
	case "asset_risk", "asset_profile":
		actions = append(actions, "补齐资产负责人、业务系统和重要性，降低后续事件分派成本。")
	case "sessions_for_ip":
		actions = append(actions, "围绕该资产查看公网访问、端口画像和最近异常波动。")
	default:
		actions = append(actions, "如果该对象长期稳定，可以继续对比行为基线判断是否异常。")
	}
	if len(rows) == 0 {
		actions = []string{"扩大观察窗口到 1 小时或 24 小时后再次查询。"}
	}
	return actions
}

func aiQueryFollowups(intent aiQueryIntent) []string {
	switch intent.ID {
	case "external_access":
		return []string{"这些公网访问里哪些风险最高？", "有没有新增的高风险端口暴露？"}
	case "incidents":
		return []string{"解释首要事件为什么严重", "这个事件关联了哪些资产和会话？"}
	case "asset_risk", "asset_profile":
		return []string{"这个资产最近连接了哪些外部地址？", "这个资产的主要风险原因是什么？"}
	case "anomalies":
		return []string{"异常增长最大的服务是什么？", "这些异常是否偏离行为基线？"}
	default:
		return []string{"最近 30 分钟哪个公网 IP 访问最多？", "今天比昨天流量增长最大的服务是什么？"}
	}
}

func aiIntentDescription(id string) string {
	switch id {
	case "sessions_for_ip":
		return "识别指定资产的关联会话，适合回答连接了谁、访问了哪些地址。"
	case "asset_profile":
		return "汇总指定资产的收发流量、关联主机对和会话。"
	case "external_access":
		return "聚合公网对端、内部资产、访问方向、端口和服务风险。"
	case "incidents":
		return "检索统一事件流和规则命中结果。"
	case "asset_risk":
		return "按资产风险评分、暴露面和事件关联排序。"
	case "anomalies":
		return "对比当前窗口和历史窗口，查找异常波动。"
	default:
		return "按现有白名单查询模板返回排行和解释。"
	}
}

func aiProfileRows(profile map[string]any) []map[string]any {
	if len(profile) == 0 {
		return []map[string]any{}
	}
	return []map[string]any{profile}
}

func topItemsToAIRows(items []model.TopItem, keyName string) []map[string]any {
	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		rows = append(rows, map[string]any{
			keyName:   item.Key,
			"key":     item.Key,
			"bytes":   item.Bytes,
			"packets": item.Packets,
		})
	}
	return rows
}

func aiQueryMinutes(question string, fallback int) int {
	matches := regexp.MustCompile(`(?i)(\d+)\s*(分钟|分|小时|天|h|hour|hours|d|day|days)`).FindStringSubmatch(question)
	if len(matches) != 3 {
		return fallback
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil || value <= 0 {
		return fallback
	}
	unit := strings.ToLower(matches[2])
	switch unit {
	case "小时", "h", "hour", "hours":
		value *= 60
	case "天", "d", "day", "days":
		value *= 1440
	}
	return normalizeQueryMinutes(value)
}

func firstIPv4(text string) string {
	return regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`).FindString(text)
}

func containsAny(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func normalizeQueryMinutes(value int) int {
	if value <= 0 {
		return 15
	}
	if value > 10080 {
		return 10080
	}
	return value
}

func (s *Server) aiOptions() aiSummaryOptions {
	ai := s.loadSystemSettings().AI
	mode := strings.TrimSpace(strings.ToLower(ai.Mode))
	if mode == "" {
		mode = "local_mock"
	}
	provider := strings.TrimSpace(ai.Provider)
	if provider == "" {
		provider = mode
	}
	model := strings.TrimSpace(ai.Model)
	if model == "" {
		model = "nexaflow-local-summary"
	}
	return aiSummaryOptions{
		Enabled:  mode != "disabled" && ai.EnabledSummaries,
		Mode:     mode,
		Provider: provider,
		Model:    model,
	}
}

func (s *Server) aiContextLimit(limit int) int {
	maxRows := s.loadSystemSettings().AI.MaxContextRows
	if maxRows > 0 && limit > maxRows {
		return maxRows
	}
	return limit
}

func buildAIIncidentSummary(options aiSummaryOptions, incident, contextData map[string]any) map[string]any {
	subject := firstString(stringValue(incident["subject"]), stringValue(contextData["subject"]), "未知事件对象")
	kind := firstString(stringValue(incident["kind"]), stringValue(contextData["kind"]), "unknown")
	severity := firstString(stringValue(incident["severity"]), maxSeverityFromRows(sliceValue(contextData["insights"])), "info")
	sessions := sliceValue(contextData["sessions"])
	insights := sliceValue(contextData["insights"])
	anomalies := sliceValue(contextData["anomalies"])
	relations := mapValue(contextData["relations"])
	relationSummary := mapValue(relations["summary"])
	dstProfile := mapValue(contextData["dst_ip_profile"])
	srcProfile := mapValue(contextData["src_ip_profile"])
	portProfile := mapValue(contextData["dst_port_profile"])
	bytes := maxUint(uint64Value(incident["bytes"]), uint64Value(relationSummary["bytes"]))
	findings := []string{
		fmt.Sprintf("事件对象 %s 当前级别为 %s，关联流量约 %s。", subject, aiSeverityText(severity), formatAIBytes(bytes)),
		fmt.Sprintf("上下文包含 %d 条关联会话、%d 条风险线索、%d 条异常波动。", len(sessions), len(insights), len(anomalies)),
	}
	if stringValue(dstProfile["ip"]) != "" {
		findings = append(findings, fmt.Sprintf("目的资产 %s 近窗口入站 %s、出站 %s。", stringValue(dstProfile["ip"]), formatAIBytes(uint64Value(dstProfile["inbound_bytes"])), formatAIBytes(uint64Value(dstProfile["outbound_bytes"]))))
	}
	if stringValue(portProfile["port"]) != "" {
		findings = append(findings, fmt.Sprintf("目的端口 %s 近窗口流量 %s，关联会话 %d 条。", stringValue(portProfile["port"]), formatAIBytes(uint64Value(portProfile["bytes"])), len(sliceValue(portProfile["flows"]))))
	}
	if len(sessions) > 0 {
		top := mapValue(sessions[0])
		findings = append(findings, "首要关联会话为 "+firstString(stringValue(top["key"]), "-")+"，流量 "+formatAIBytes(uint64Value(top["bytes"]))+"。")
	}
	if len(anomalies) > 0 {
		top := mapValue(anomalies[0])
		findings = append(findings, "最近异常变化："+firstString(stringValue(top["summary"]), firstString(stringValue(top["key"]), "未知异常"))+"。")
	}
	evidence := []string{
		"事件类型：" + aiIncidentKindText(kind),
		"关联会话数：" + strconv.Itoa(len(sessions)),
		"关联风险线索：" + strconv.Itoa(len(insights)),
		"关联异常波动：" + strconv.Itoa(len(anomalies)),
	}
	if stringValue(srcProfile["ip"]) != "" {
		evidence = append(evidence, "源资产画像："+stringValue(srcProfile["ip"]))
	}
	if stringValue(dstProfile["ip"]) != "" {
		evidence = append(evidence, "目的资产画像："+stringValue(dstProfile["ip"]))
	}
	if stringValue(portProfile["port"]) != "" {
		evidence = append(evidence, "端口画像："+stringValue(portProfile["port"]))
	}
	actions := []string{
		"优先查看事件上下文中的关联会话和关联端口，确认是否为计划内业务流量。",
		"核对事件对象的资产负责人、业务标签和公网暴露策略。",
	}
	if severity == "critical" {
		actions = append([]string{"先确认是否需要临时收敛访问来源或提高监控级别。"}, actions...)
	}
	if !options.Enabled {
		return disabledAISummary(options, "incident", subject)
	}
	return aiSummary(options, "incident", subject, "AI 事件摘要", fmt.Sprintf("%s 触发 %s，系统已关联会话、风险线索和异常波动生成调查结论草案。", subject, aiIncidentKindText(kind)), confidenceByContext(len(sessions)+len(insights)+len(anomalies)), findings, evidence, actions)
}

func buildAIAssetSummary(options aiSummaryOptions, ip string, risk, profile map[string]any) map[string]any {
	name := stringValue(risk["name"])
	if name == "" {
		name = ip
	}
	riskLevel := firstString(stringValue(risk["risk_level"]), "unknown")
	externalPeers := int64Value(risk["external_peers"])
	exposedServices := int64Value(risk["exposed_services"])
	openIncidents := int64Value(risk["open_incidents"])
	topPairs := sliceValue(profile["top_pairs"])
	topFlows := sliceValue(profile["top_flows"])
	findings := []string{
		fmt.Sprintf("资产 %s 当前风险等级为 %s，风险评分 %d。", name, assetRiskLevelText(riskLevel), int64Value(risk["risk_score"])),
		fmt.Sprintf("公网对端 %d 个，暴露服务 %d 个，开放事件 %d 个。", externalPeers, exposedServices, openIncidents),
	}
	if finding := stringValue(risk["top_finding"]); finding != "" {
		findings = append(findings, "主要风险原因："+finding+"。")
	}
	if len(topFlows) > 0 {
		top := mapValue(topFlows[0])
		findings = append(findings, "首要会话："+firstString(stringValue(top["key"]), "-")+"，流量 "+formatAIBytes(uint64Value(top["bytes"]))+"。")
	}
	evidence := []string{
		"总流量：" + formatAIBytes(uint64Value(risk["total_bytes"])),
		"公网流量：" + formatAIBytes(uint64Value(risk["external_bytes"])),
		"关联主机对：" + strconv.Itoa(len(topPairs)),
		"关联会话：" + strconv.Itoa(len(topFlows)),
	}
	actions := []string{
		"补齐资产负责人、业务系统、环境和重要性标签。",
		"复核公网访问来源、暴露端口和白名单策略。",
	}
	if openIncidents > 0 {
		actions = append([]string{"先处理该资产关联的开放事件，再评估是否需要调整检测规则。"}, actions...)
	}
	if !options.Enabled {
		return disabledAISummary(options, "asset", ip)
	}
	return aiSummary(options, "asset", ip, "AI 资产摘要", fmt.Sprintf("%s 的风险主要来自公网暴露、事件关联和历史行为画像，建议按资产归属和暴露面优先处置。", name), confidenceByContext(len(topPairs)+len(topFlows)+int(openIncidents)), findings, evidence, actions)
}

func buildAIReportSummary(options aiSummaryOptions, report map[string]any) map[string]any {
	summary := mapValue(report["summary"])
	assetRisks := sliceValue(report["asset_risks"])
	incidents := sliceValue(report["incidents"])
	anomalies := sliceValue(report["anomalies"])
	exposures := sliceValue(report["exposures"])
	minutes := int64Value(summary["minutes"])
	riskSentence := "当前窗口未发现明显严重风险。"
	if int64Value(summary["critical_assets"]) > 0 || int64Value(summary["critical_incidents"]) > 0 {
		riskSentence = "当前窗口存在严重资产或严重事件，需要优先处置。"
	} else if int64Value(summary["high_risk_services"]) > 0 || int64Value(summary["critical_anomalies"]) > 0 {
		riskSentence = "当前窗口存在高风险服务或严重异常，建议继续下钻确认。"
	}
	findings := []string{
		fmt.Sprintf("观察范围 %d 分钟，总流量 %s，峰值 %.2f Mbps。", minutes, formatAIBytes(uint64Value(summary["bytes"])), float64Value(summary["peak_mbps"])),
		fmt.Sprintf("资产 %d 个，其中严重资产 %d 个；开放事件 %d 个，其中严重事件 %d 个。", int64Value(summary["asset_count"]), int64Value(summary["critical_assets"]), int64Value(summary["open_incidents"]), int64Value(summary["critical_incidents"])),
		fmt.Sprintf("异常 %d 个，暴露服务 %d 个，高风险服务 %d 个。", int64Value(summary["anomaly_count"]), int64Value(summary["exposed_services"]), int64Value(summary["high_risk_services"])),
	}
	if len(assetRisks) > 0 {
		top := mapValue(assetRisks[0])
		findings = append(findings, "最高风险资产："+firstString(stringValue(top["ip"]), "-")+"，原因："+firstString(stringValue(top["top_finding"]), "无显著风险")+"。")
	}
	evidence := []string{
		"资产风险样本：" + strconv.Itoa(len(assetRisks)),
		"事件样本：" + strconv.Itoa(len(incidents)),
		"异常样本：" + strconv.Itoa(len(anomalies)),
		"暴露服务样本：" + strconv.Itoa(len(exposures)),
	}
	actions := []string{
		"先处理严重资产和开放事件，再复核异常波动是否与业务变更相关。",
		"对高风险服务补充资产归属和访问策略，必要时生成规则或白名单建议。",
		"把本摘要作为巡检报告草案，结合事件备注补充人工结论。",
	}
	if !options.Enabled {
		return disabledAISummary(options, "report", "overview")
	}
	return aiSummary(options, "report", "overview", "AI 巡检摘要", riskSentence, confidenceByContext(len(assetRisks)+len(incidents)+len(anomalies)+len(exposures)), findings, evidence, actions)
}

func aiSummary(options aiSummaryOptions, kind, subject, title, summary string, confidence float64, findings, evidence, actions []string) map[string]any {
	return map[string]any{
		"enabled":      options.Enabled,
		"mode":         options.Mode,
		"provider":     options.Provider,
		"model":        options.Model,
		"kind":         kind,
		"subject":      subject,
		"title":        title,
		"summary":      summary,
		"confidence":   confidence,
		"findings":     findings,
		"evidence":     evidence,
		"actions":      actions,
		"generated_at": time.Now().Unix(),
	}
}

func disabledAISummary(options aiSummaryOptions, kind, subject string) map[string]any {
	return aiSummary(options, kind, subject, "AI 摘要已关闭", "当前 `NEXAFLOW_AI_MODE=disabled`，系统只返回基础上下文，不生成 AI 摘要。", 0, []string{}, []string{}, []string{"设置 NEXAFLOW_AI_MODE=local_mock 可启用本地摘要，或配置外部模型网关。"})
}

func confidenceByContext(count int) float64 {
	switch {
	case count >= 8:
		return 0.86
	case count >= 4:
		return 0.74
	case count >= 1:
		return 0.62
	default:
		return 0.45
	}
}

func findAIIncident(rows []map[string]any, id, subject, kind string) map[string]any {
	for _, row := range rows {
		if id != "" && stringValue(row["id"]) == id {
			return row
		}
		if subject != "" && stringValue(row["subject"]) == subject && (kind == "" || stringValue(row["kind"]) == kind) {
			return row
		}
	}
	return map[string]any{}
}

func aiIncidentContextUsable(contextData map[string]any) bool {
	if len(sliceValue(contextData["sessions"])) > 0 || len(sliceValue(contextData["insights"])) > 0 || len(sliceValue(contextData["anomalies"])) > 0 {
		return true
	}
	for _, key := range []string{"ip_profile", "src_ip_profile", "dst_ip_profile", "port_profile", "dst_port_profile"} {
		if len(mapValue(contextData[key])) > 0 {
			return true
		}
	}
	return false
}

func findMapByString(rows []map[string]any, field, value string) map[string]any {
	for _, row := range rows {
		if stringValue(row[field]) == value {
			return row
		}
	}
	return map[string]any{}
}

func maxSeverityFromRows(rows []any) string {
	severity := "info"
	for _, row := range rows {
		next := stringValue(mapValue(row)["severity"])
		if severityWeight(next) > severityWeight(severity) {
			severity = next
		}
	}
	return severity
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maxUint(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func formatAIBytes(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	amount := float64(value)
	unit := units[0]
	for i := 1; i < len(units) && amount >= 1024; i++ {
		amount = amount / 1024
		unit = units[i]
	}
	if unit == "B" {
		return strconv.FormatUint(value, 10) + " B"
	}
	return fmt.Sprintf("%.2f %s", amount, unit)
}

func aiSeverityText(severity string) string {
	switch severity {
	case "critical":
		return "严重"
	case "warning":
		return "警告"
	case "info":
		return "提示"
	default:
		return "未知"
	}
}

func aiIncidentKindText(kind string) string {
	switch kind {
	case "heavy_flow":
		return "重流量会话"
	case "source_fanout":
		return "源主机扇出"
	case "external_session_burst":
		return "公网会话突增"
	case "threshold_alert":
		return "阈值告警"
	case "collector_offline":
		return "采集离线"
	case "custom_rule":
		return "自定义规则命中"
	default:
		return kind
	}
}

func assetRiskLevelText(level string) string {
	switch level {
	case "critical":
		return "严重"
	case "warning":
		return "关注"
	case "healthy":
		return "健康"
	default:
		return "未知"
	}
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
