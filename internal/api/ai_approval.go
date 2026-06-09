package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"nexaflow/internal/config"
	"nexaflow/internal/model"
)

type aiApprovalRequest struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Status      string         `json:"status"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Target      string         `json:"target"`
	Summary     string         `json:"summary"`
	Confidence  float64        `json:"confidence"`
	Evidence    []string       `json:"evidence"`
	Actions     []string       `json:"actions"`
	Payload     map[string]any `json:"payload"`
	CreatedBy   string         `json:"created_by"`
	CreatedAt   int64          `json:"created_at"`
	ReviewedBy  string         `json:"reviewed_by,omitempty"`
	ReviewedAt  int64          `json:"reviewed_at,omitempty"`
	ReviewNote  string         `json:"review_note,omitempty"`
	AppliedAt   int64          `json:"applied_at,omitempty"`
	ApplyResult string         `json:"apply_result,omitempty"`
}

type aiApprovalStore struct {
	Requests []aiApprovalRequest `json:"requests"`
}

type aiApprovalCount struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type aiApprovalBulkReviewResult struct {
	Action   string              `json:"action"`
	Reviewed int                 `json:"reviewed"`
	Skipped  int                 `json:"skipped"`
	Requests []aiApprovalRequest `json:"requests"`
	Errors   []string            `json:"errors"`
}

func (s *Server) aiApprovalRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		items, err := s.loadAIApprovalRequests()
		if status != "" {
			items = filterAIApprovalRequests(items, status)
		}
		writeJSON(w, map[string]any{"data": items, "degraded": err != nil})
	case http.MethodPost:
		var body struct {
			Action  string            `json:"action"`
			ID      string            `json:"id"`
			IDs     []string          `json:"ids"`
			Note    string            `json:"note"`
			Request aiApprovalRequest `json:"request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		action := strings.TrimSpace(body.Action)
		if action == "" {
			result, err := s.createAIApprovalRequest(r, body.Request)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"data": result})
			return
		}
		if len(body.IDs) > 0 {
			result, err := s.bulkReviewAIApprovalRequests(r, body.IDs, action, strings.TrimSpace(body.Note))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"data": result})
			return
		}
		result, err := s.reviewAIApprovalRequest(r, strings.TrimSpace(body.ID), action, strings.TrimSpace(body.Note))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"data": result})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) aiApprovalStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	items, err := s.loadAIApprovalRequests()
	writeJSON(w, map[string]any{"data": buildAIApprovalStats(items, time.Now().Unix()), "degraded": err != nil})
}

func (s *Server) bulkReviewAIApprovalRequests(r *http.Request, ids []string, action, note string) (aiApprovalBulkReviewResult, error) {
	result := aiApprovalBulkReviewResult{Action: action, Requests: []aiApprovalRequest{}, Errors: []string{}}
	if action != "reject" {
		return result, fmt.Errorf("bulk review only supports reject")
	}
	seen := map[string]bool{}
	normalizedIDs := []string{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		normalizedIDs = append(normalizedIDs, id)
	}
	if len(normalizedIDs) == 0 {
		return result, fmt.Errorf("ids are required")
	}
	items, err := s.loadAIApprovalRequests()
	if err != nil {
		return result, err
	}
	positions := map[string]int{}
	for i, item := range items {
		positions[item.ID] = i
	}
	reviewer := auditActor(r)
	now := time.Now().Unix()
	for _, id := range normalizedIDs {
		index, ok := positions[id]
		if !ok {
			result.Skipped++
			result.Errors = append(result.Errors, id+": not found")
			continue
		}
		request := items[index]
		if request.Status != "pending" {
			result.Skipped++
			result.Errors = append(result.Errors, id+": already "+request.Status)
			continue
		}
		request.Status = "rejected"
		request.ReviewedBy = reviewer
		request.ReviewedAt = now
		request.ReviewNote = note
		items[index] = request
		result.Reviewed++
		result.Requests = append(result.Requests, request)
	}
	if result.Reviewed == 0 {
		return result, fmt.Errorf("no pending approval requests matched")
	}
	if err := s.saveAIApprovalRequests(items); err != nil {
		return result, err
	}
	for _, request := range result.Requests {
		s.audit(r, "ai.approval.reject", request.ID, "批量驳回 AI 建议："+request.Title, map[string]any{"id": request.ID, "type": request.Type, "note": note, "bulk": true})
	}
	s.audit(r, "ai.approval.bulk_reject", "ai_approval_requests", "批量驳回 AI 建议："+strconv.Itoa(result.Reviewed)+" 条", map[string]any{
		"ids":      normalizedIDs,
		"reviewed": result.Reviewed,
		"skipped":  result.Skipped,
		"errors":   result.Errors,
		"note":     note,
	})
	return result, nil
}

func (s *Server) createAIApprovalRequest(r *http.Request, request aiApprovalRequest) (aiApprovalRequest, error) {
	request.Type = strings.TrimSpace(request.Type)
	request.Title = strings.TrimSpace(request.Title)
	request.Target = strings.TrimSpace(request.Target)
	if request.Type == "" || request.Title == "" || request.Target == "" {
		return request, fmt.Errorf("type, title and target are required")
	}
	if len(request.Payload) == 0 {
		return request, fmt.Errorf("payload is required")
	}
	request.ID = strings.TrimSpace(request.ID)
	if request.ID == "" {
		request.ID = "ai-approval-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	request.Status = "pending"
	request.CreatedBy = auditActor(r)
	request.CreatedAt = time.Now().Unix()
	items, _ := s.loadAIApprovalRequests()
	items = upsertAIApprovalRequest(items, request)
	if err := s.saveAIApprovalRequests(items); err != nil {
		return request, err
	}
	s.audit(r, "ai.approval.create", request.ID, "提交 AI 建议审批："+request.Title, map[string]any{
		"id":     request.ID,
		"type":   request.Type,
		"target": request.Target,
	})
	return request, nil
}

func (s *Server) reviewAIApprovalRequest(r *http.Request, id, action, note string) (aiApprovalRequest, error) {
	if id == "" {
		return aiApprovalRequest{}, fmt.Errorf("id is required")
	}
	if action != "approve" && action != "reject" {
		return aiApprovalRequest{}, fmt.Errorf("action must be approve or reject")
	}
	items, err := s.loadAIApprovalRequests()
	if err != nil {
		return aiApprovalRequest{}, err
	}
	index := -1
	for i, item := range items {
		if item.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return aiApprovalRequest{}, fmt.Errorf("approval request not found")
	}
	request := items[index]
	if request.Status != "pending" {
		return request, fmt.Errorf("approval request is already %s", request.Status)
	}
	request.ReviewedBy = auditActor(r)
	request.ReviewedAt = time.Now().Unix()
	request.ReviewNote = note
	if action == "reject" {
		request.Status = "rejected"
		items[index] = request
		if err := s.saveAIApprovalRequests(items); err != nil {
			return request, err
		}
		s.audit(r, "ai.approval.reject", request.ID, "驳回 AI 建议："+request.Title, map[string]any{"id": request.ID, "type": request.Type, "note": note})
		return request, nil
	}
	applyResult, err := s.applyAIApprovalRequest(r, request)
	if err != nil {
		return request, err
	}
	request.Status = "approved"
	request.AppliedAt = time.Now().Unix()
	request.ApplyResult = applyResult
	items[index] = request
	if err := s.saveAIApprovalRequests(items); err != nil {
		return request, err
	}
	s.audit(r, "ai.approval.approve", request.ID, "批准 AI 建议："+request.Title, map[string]any{"id": request.ID, "type": request.Type, "result": applyResult})
	return request, nil
}

func (s *Server) applyAIApprovalRequest(r *http.Request, request aiApprovalRequest) (string, error) {
	switch request.Type {
	case "rule":
		ruleData := mapValue(request.Payload["proposed_rule"])
		if len(ruleData) == 0 {
			ruleData = request.Payload
		}
		data, err := json.Marshal(ruleData)
		if err != nil {
			return "", err
		}
		var rule model.DetectionRule
		if err := json.Unmarshal(data, &rule); err != nil {
			return "", err
		}
		rule.ID = ""
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Metric) == "" || rule.Threshold <= 0 {
			return "", fmt.Errorf("invalid proposed rule")
		}
		runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
		rule.ID = "rule-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		rule.UpdatedAt = time.Now().Unix()
		runtime.Alerts.DetectionRules = upsertDetectionRule(runtime.Alerts.DetectionRules, rule)
		if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
			return "", err
		}
		s.configSnapshot(r, "rules", rule.ID, "ai.approval.apply.rule", "AI 审批保存检测规则："+rule.Name, config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
		return "saved rule " + rule.ID, nil
	case "silence":
		silence := mapValue(request.Payload["proposed_silence"])
		subject := strings.TrimSpace(firstString(stringValue(silence["subject"]), stringValue(request.Payload["subject"]), request.Target))
		if subject == "" {
			return "", fmt.Errorf("silence subject is required")
		}
		runtime := config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config))
		runtime.Alerts.SilencedSubjects = append(runtime.Alerts.SilencedSubjects, subject)
		runtime.Alerts.SilencedSubjects = normalizeRuntimeSilencedSubjects(runtime.Alerts.SilencedSubjects)
		if err := config.SaveRuntime(s.config.RuntimePath, runtime); err != nil {
			return "", err
		}
		s.configSnapshot(r, "alerts", subject, "ai.approval.apply.silence", "AI 审批加入白名单/静默名单："+subject, config.LoadRuntime(s.config.RuntimePath, config.DefaultRuntime(s.config)))
		return "silenced " + subject, nil
	case "asset_enrichment":
		metadata := mapValue(request.Payload["proposed_metadata"])
		if len(metadata) == 0 {
			metadata = request.Payload
		}
		if strings.TrimSpace(stringValue(metadata["ip"])) == "" {
			metadata["ip"] = request.Target
		}
		if strings.TrimSpace(stringValue(metadata["ip"])) == "" {
			return "", fmt.Errorf("asset ip is required")
		}
		data, err := s.store.UpdateAssetMetadata(r.Context(), metadata)
		if err != nil {
			return "", err
		}
		target := "asset:" + stringValue(data["ip"])
		s.audit(r, "ai.approval.apply.asset_metadata", target, "AI 审批更新资产元数据："+stringValue(data["ip"]), map[string]any{"id": request.ID, "ip": data["ip"]})
		return "updated asset " + stringValue(data["ip"]), nil
	default:
		return "", fmt.Errorf("unsupported approval type: %s", request.Type)
	}
}

func (s *Server) aiApprovalRequestsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.loadSystemSettings().Data.ExportEnabled {
		http.Error(w, "export is disabled", http.StatusForbidden)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := queryLimit(r, 200, 2000)
	items, err := s.loadAIApprovalRequests()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if status != "" {
		items = filterAIApprovalRequests(items, status)
	}
	if len(items) > limit {
		items = items[:limit]
	}
	body, err := aiApprovalRequestsCSV(items)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	statusPart := safeFilenamePart(firstString(status, "all"))
	filename := fmt.Sprintf("nexaflow-ai-approvals-%s-%s.csv", statusPart, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, writeErr := w.Write(body); writeErr == nil {
		s.audit(r, "ai.approval.export", "ai_approval_requests", "导出 AI 审批队列："+filename, map[string]any{
			"format": "csv",
			"status": status,
			"limit":  limit,
			"rows":   len(items),
			"bytes":  len(body),
		})
	}
}

func aiApprovalRequestsCSV(items []aiApprovalRequest) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{
		"created_time",
		"id",
		"type",
		"status",
		"severity",
		"title",
		"target",
		"summary",
		"confidence",
		"evidence",
		"actions",
		"created_by",
		"reviewed_by",
		"reviewed_time",
		"review_note",
		"applied_time",
		"apply_result",
		"payload",
	}); err != nil {
		return nil, err
	}
	for _, item := range items {
		payload, err := json.Marshal(item.Payload)
		if err != nil {
			return nil, err
		}
		if err := writer.Write([]string{
			formatUnixTime(item.CreatedAt),
			item.ID,
			item.Type,
			item.Status,
			item.Severity,
			item.Title,
			item.Target,
			item.Summary,
			strconv.FormatFloat(item.Confidence, 'f', 2, 64),
			strings.Join(item.Evidence, "；"),
			strings.Join(item.Actions, "；"),
			item.CreatedBy,
			item.ReviewedBy,
			formatUnixTime(item.ReviewedAt),
			item.ReviewNote,
			formatUnixTime(item.AppliedAt),
			item.ApplyResult,
			string(payload),
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

func buildAIApprovalStats(items []aiApprovalRequest, now int64) map[string]any {
	if now <= 0 {
		now = time.Now().Unix()
	}
	statusCounts := map[string]int{}
	typeCounts := map[string]int{}
	severityCounts := map[string]int{}
	pendingByType := map[string]int{}
	pendingBySeverity := map[string]int{}
	totalReviewSeconds := int64(0)
	reviewedCount := 0
	oldestPendingAge := int64(0)
	overduePending := 0
	criticalPending := 0
	staleThreshold := int64(24 * 60 * 60)

	for _, item := range items {
		status := firstString(strings.TrimSpace(item.Status), "pending")
		typ := firstString(strings.TrimSpace(item.Type), "unknown")
		severity := firstString(strings.TrimSpace(item.Severity), "info")
		statusCounts[status]++
		typeCounts[typ]++
		severityCounts[severity]++
		if status == "pending" {
			age := now - item.CreatedAt
			if age < 0 {
				age = 0
			}
			if age > oldestPendingAge {
				oldestPendingAge = age
			}
			if age >= staleThreshold {
				overduePending++
			}
			if severity == "critical" {
				criticalPending++
			}
			pendingByType[typ]++
			pendingBySeverity[severity]++
		}
		if item.ReviewedAt > 0 && item.CreatedAt > 0 && item.ReviewedAt >= item.CreatedAt {
			totalReviewSeconds += item.ReviewedAt - item.CreatedAt
			reviewedCount++
		}
	}

	avgReviewSeconds := int64(0)
	if reviewedCount > 0 {
		avgReviewSeconds = totalReviewSeconds / int64(reviewedCount)
	}
	summary := fmt.Sprintf("AI 审批队列共有 %d 条请求，%d 条待审批。", len(items), statusCounts["pending"])
	if criticalPending > 0 || overduePending > 0 {
		summary = fmt.Sprintf("AI 审批队列共有 %d 条请求，%d 条待审批，其中 %d 条严重、%d 条超过 24 小时。", len(items), statusCounts["pending"], criticalPending, overduePending)
	}
	recommendations := aiApprovalStatsRecommendations(statusCounts["pending"], criticalPending, overduePending, oldestPendingAge)
	return map[string]any{
		"generated_at":                 now,
		"total":                        len(items),
		"pending":                      statusCounts["pending"],
		"approved":                     statusCounts["approved"],
		"rejected":                     statusCounts["rejected"],
		"critical_pending":             criticalPending,
		"overdue_pending":              overduePending,
		"oldest_pending_age_seconds":   oldestPendingAge,
		"average_review_seconds":       avgReviewSeconds,
		"reviewed_count":               reviewedCount,
		"status_counts":                approvalCounts(statusCounts, aiApprovalStatusLabel),
		"type_counts":                  approvalCounts(typeCounts, aiApprovalTypeLabel),
		"severity_counts":              approvalCounts(severityCounts, aiApprovalSeverityLabel),
		"pending_type_counts":          approvalCounts(pendingByType, aiApprovalTypeLabel),
		"pending_severity_counts":      approvalCounts(pendingBySeverity, aiApprovalSeverityLabel),
		"stale_threshold_seconds":      staleThreshold,
		"summary":                      summary,
		"recommendations":              recommendations,
		"requires_operator_attention":  criticalPending > 0 || overduePending > 0 || statusCounts["pending"] >= 10,
		"approval_completion_rate":     ratio(statusCounts["approved"]+statusCounts["rejected"], len(items)),
		"approval_rejection_rate":      ratio(statusCounts["rejected"], statusCounts["approved"]+statusCounts["rejected"]),
		"pending_criticality_score":    min(100, criticalPending*25+overduePending*15+statusCounts["pending"]*3),
		"oldest_pending_age_readable":  durationText(oldestPendingAge),
		"average_review_time_readable": durationText(avgReviewSeconds),
	}
}

func aiApprovalStatsRecommendations(pending, criticalPending, overduePending int, oldestPendingAge int64) []string {
	recommendations := []string{}
	if criticalPending > 0 {
		recommendations = append(recommendations, "优先处理严重级别的 AI 建议，避免高风险规则、白名单或资产画像建议长期悬置。")
	}
	if overduePending > 0 {
		recommendations = append(recommendations, "存在超过 24 小时未处理的审批项，建议安排值班人员复核并补充处理备注。")
	}
	if pending >= 10 {
		recommendations = append(recommendations, "待审批积压较多，建议按类型分派规则、白名单和资产画像负责人。")
	}
	if oldestPendingAge > 0 && oldestPendingAge < 24*60*60 && len(recommendations) == 0 {
		recommendations = append(recommendations, "队列处于可控状态，建议保持每日复核，确保 AI 建议可追溯闭环。")
	}
	if pending == 0 {
		recommendations = append(recommendations, "当前无待审批建议，可继续关注新增治理建议和规则效果评估。")
	}
	return recommendations
}

func approvalCounts(counts map[string]int, label func(string) string) []aiApprovalCount {
	items := make([]aiApprovalCount, 0, len(counts))
	for key, count := range counts {
		if count <= 0 {
			continue
		}
		items = append(items, aiApprovalCount{Key: key, Label: label(key), Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	return items
}

func aiApprovalStatusLabel(value string) string {
	switch value {
	case "pending":
		return "待审批"
	case "approved":
		return "已批准"
	case "rejected":
		return "已驳回"
	default:
		return firstString(value, "未知")
	}
}

func aiApprovalTypeLabel(value string) string {
	switch value {
	case "rule":
		return "检测规则"
	case "silence":
		return "白名单"
	case "asset_enrichment":
		return "资产画像"
	default:
		return firstString(value, "未知")
	}
}

func aiApprovalSeverityLabel(value string) string {
	switch value {
	case "critical":
		return "严重"
	case "warning":
		return "警告"
	case "info":
		return "提示"
	default:
		return firstString(value, "未知")
	}
}

func durationText(seconds int64) string {
	if seconds <= 0 {
		return "-"
	}
	if seconds >= 24*60*60 {
		return strconv.FormatInt(seconds/(24*60*60), 10) + " 天"
	}
	if seconds >= 60*60 {
		return strconv.FormatInt(seconds/(60*60), 10) + " 小时"
	}
	if seconds >= 60 {
		return strconv.FormatInt(seconds/60, 10) + " 分钟"
	}
	return strconv.FormatInt(seconds, 10) + " 秒"
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func formatUnixTime(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Format(time.RFC3339)
}

func safeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "all"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
}

func (s *Server) aiApprovalRequestsPath() string {
	return filepath.Join(filepath.Dir(s.config.RuntimePath), "ai_approval_requests.json")
}

func (s *Server) loadAIApprovalRequests() ([]aiApprovalRequest, error) {
	data, err := os.ReadFile(s.aiApprovalRequestsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []aiApprovalRequest{}, nil
		}
		return []aiApprovalRequest{}, err
	}
	var store aiApprovalStore
	if err := json.Unmarshal(data, &store); err != nil {
		return []aiApprovalRequest{}, err
	}
	return store.Requests, nil
}

func (s *Server) saveAIApprovalRequests(items []aiApprovalRequest) error {
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt > items[j].CreatedAt
	})
	path := s.aiApprovalRequestsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(aiApprovalStore{Requests: items}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func upsertAIApprovalRequest(items []aiApprovalRequest, request aiApprovalRequest) []aiApprovalRequest {
	for i, item := range items {
		if item.ID == request.ID {
			items[i] = request
			return items
		}
	}
	return append(items, request)
}

func filterAIApprovalRequests(items []aiApprovalRequest, status string) []aiApprovalRequest {
	result := []aiApprovalRequest{}
	for _, item := range items {
		if item.Status == status {
			result = append(result, item)
		}
	}
	return result
}

func normalizeRuntimeSilencedSubjects(subjects []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, subject := range subjects {
		subject = strings.TrimSpace(subject)
		if subject == "" || seen[subject] {
			continue
		}
		seen[subject] = true
		result = append(result, subject)
	}
	return result
}
