package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nexaflow/internal/config"
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
	mux.HandleFunc("/api/v1/dashboard/summary", s.summary)
	mux.HandleFunc("/api/v1/traffic/topn", s.topn)
	mux.HandleFunc("/api/v1/traffic/timeseries", s.timeseries)
	mux.HandleFunc("/api/v1/traffic/ip-profile", s.ipProfile)
	mux.HandleFunc("/api/v1/traffic/port-profile", s.portProfile)
	mux.HandleFunc("/api/v1/traffic/windows", s.windows)
	mux.HandleFunc("/api/v1/traffic/matrix", s.matrix)
	mux.HandleFunc("/api/v1/traffic/service-map", s.serviceMap)
	mux.HandleFunc("/api/v1/traffic/service-exposure", s.serviceExposure)
	mux.HandleFunc("/api/v1/traffic/protocol-timeseries", s.protocolTimeseries)
	mux.HandleFunc("/api/v1/traffic/port-timeseries", s.portTimeseries)
	mux.HandleFunc("/api/v1/traffic/direction-timeseries", s.directionTimeseries)
	mux.HandleFunc("/api/v1/traffic/search", s.search)
	mux.HandleFunc("/api/v1/traffic/analysis", s.trafficAnalysis)
	mux.HandleFunc("/api/v1/traffic/changes", s.trafficChanges)
	mux.HandleFunc("/api/v1/assets", s.assets)
	mux.HandleFunc("/api/v1/security/insights", s.securityInsights)
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

func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Assets(r.Context(), queryMinutes(r), queryLimit(r, 50, 500))
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) securityInsights(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.SecurityInsights(r.Context(), queryMinutes(r), queryLimit(r, 50, 200))
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	data = filterSilencedMaps(data, runtime.Alerts.SilencedSubjects, "subject")
	writeJSON(w, map[string]any{"data": data, "degraded": err != nil})
}

func (s *Server) collectors(w http.ResponseWriter, _ *http.Request) {
	runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
	writeJSON(w, map[string]any{
		"data": []map[string]any{{
			"id":         s.config.CollectorID,
			"source_id":  runtime.SourceID,
			"status":     "online",
			"mode":       runtime.Mode,
			"iface":      runtime.Iface,
			"bpf_filter": runtime.BPFFilter,
			"updated_at": runtime.UpdatedAt,
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
	data["collector"] = map[string]any{
		"id":         s.config.CollectorID,
		"source_id":  runtime.SourceID,
		"mode":       runtime.Mode,
		"iface":      runtime.Iface,
		"bpf_filter": runtime.BPFFilter,
		"alerts":     runtime.Alerts,
		"updated_at": runtime.UpdatedAt,
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
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS")
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

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func alertsEmpty(alerts config.Alerts) bool {
	return alerts.FlowBytes == 0 &&
		alerts.FlowShare == 0 &&
		alerts.SourcePackets == 0 &&
		alerts.LinkUtilization == 0 &&
		len(alerts.SilencedSubjects) == 0
}
