package api

import (
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
