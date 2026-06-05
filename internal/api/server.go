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
	"os"
	"path/filepath"
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
	data, err := s.store.BehaviorBaseline(r.Context(), minutes, queryBaselineMinutes(r, minutes), queryLimit(r, 10, 50))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) capacityPlanning(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.CapacityPlanning(r.Context(), queryMinutes(r), queryLimit(r, 10, 50), s.config.BandwidthMbps)
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
	return strings.TrimSpace(s.config.AuthPassword) != "" || strings.TrimSpace(s.config.AuthReadOnlyPassword) != ""
}

func (s *Server) loginRole(password string) string {
	if strings.TrimSpace(s.config.AuthPassword) != "" && subtle.ConstantTimeCompare([]byte(password), []byte(s.config.AuthPassword)) == 1 {
		return authRoleAdmin
	}
	if strings.TrimSpace(s.config.AuthReadOnlyPassword) != "" && subtle.ConstantTimeCompare([]byte(password), []byte(s.config.AuthReadOnlyPassword)) == 1 {
		return authRoleViewer
	}
	return ""
}

func requestNeedsWriteAccess(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
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
	token, err := s.signAuthToken(actor, role, time.Now().Add(12*time.Hour).Unix())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((12 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
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

func queryBaselineMinutes(r *http.Request, minutes int) int {
	fallback := max(minutes*8, 60)
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

type aiSummaryOptions struct {
	Enabled  bool
	Mode     string
	Provider string
	Model    string
}

func (s *Server) aiOptions() aiSummaryOptions {
	mode := strings.TrimSpace(strings.ToLower(s.config.AIMode))
	if mode == "" {
		mode = "local_mock"
	}
	provider := strings.TrimSpace(s.config.AIProvider)
	if provider == "" {
		provider = mode
	}
	model := strings.TrimSpace(s.config.AIModel)
	if model == "" {
		model = "nexaflow-local-summary"
	}
	return aiSummaryOptions{
		Enabled:  mode != "disabled",
		Mode:     mode,
		Provider: provider,
		Model:    model,
	}
}

func (s *Server) aiContextLimit(limit int) int {
	if s.config.AIMaxContextRows > 0 && limit > s.config.AIMaxContextRows {
		return s.config.AIMaxContextRows
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
