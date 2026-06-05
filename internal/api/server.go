package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io/fs"
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
	mux.HandleFunc("/api/v1/system/audit-events", s.auditEvents)
	mux.HandleFunc("/api/v1/system/config-versions", s.configVersions)
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
