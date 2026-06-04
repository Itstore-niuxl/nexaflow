package api

import (
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
	mux.HandleFunc("/api/v1/dashboard/summary", s.summary)
	mux.HandleFunc("/api/v1/traffic/topn", s.topn)
	mux.HandleFunc("/api/v1/traffic/timeseries", s.timeseries)
	mux.HandleFunc("/api/v1/traffic/ip-profile", s.ipProfile)
	mux.HandleFunc("/api/v1/traffic/port-profile", s.portProfile)
	mux.HandleFunc("/api/v1/traffic/windows", s.windows)
	mux.HandleFunc("/api/v1/traffic/matrix", s.matrix)
	mux.HandleFunc("/api/v1/traffic/service-map", s.serviceMap)
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
	return cors(mux)
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
		"alerts":       runtime.Alerts,
		"updated_at":   runtime.UpdatedAt,
	}
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
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
