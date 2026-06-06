package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nexaflow/internal/config"
)

type aiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiChatRequest struct {
	Model       string          `json:"model"`
	Messages    []aiChatMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type aiChatResponse struct {
	Choices []struct {
		Message aiChatMessage `json:"message"`
	} `json:"choices"`
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func (s *Server) enhanceAISummary(ctx context.Context, local map[string]any, contextData map[string]any) (map[string]any, error) {
	ai := s.loadSystemSettings().AI
	if !shouldCallExternalAI(ai) || !boolValue(local["enabled"]) {
		local["provider_status"] = "local"
		return local, nil
	}
	enhanced, err := callExternalAISummary(ctx, ai, local, contextData)
	if err != nil {
		local["provider_status"] = "fallback"
		local["provider_error"] = err.Error()
		return local, err
	}
	return mergeExternalAISummary(local, enhanced), nil
}

func shouldCallExternalAI(ai config.AISettings) bool {
	mode := strings.ToLower(strings.TrimSpace(ai.Mode))
	if mode == "" || mode == "disabled" || mode == "local_mock" {
		return false
	}
	return strings.TrimSpace(ai.BaseURL) != "" && strings.TrimSpace(ai.APIKey) != ""
}

func callExternalAISummary(ctx context.Context, ai config.AISettings, local, contextData map[string]any) (map[string]any, error) {
	target, err := url.Parse(strings.TrimRight(ai.BaseURL, "/") + "/chat/completions")
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("AI Base URL 格式不正确")
	}
	model := strings.TrimSpace(ai.Model)
	if model == "" {
		model = "nexaflow-local-summary"
	}
	payload := map[string]any{
		"local_summary": local,
		"context":       contextData,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	requestBody, err := json.Marshal(aiChatRequest{
		Model: model,
		Messages: []aiChatMessage{
			{
				Role: "system",
				Content: strings.Join([]string{
					"你是 NexaFlow 网络流量分析系统的企业级 AI 分析助手。",
					"只能基于用户提供的 JSON 上下文生成结论，不得编造 IP、端口、资产、风险或数值。",
					"返回 JSON 对象，字段仅包含 summary、findings、actions、confidence、evidence。",
					"findings、actions、evidence 必须是中文字符串数组，summary 必须是中文短段落，confidence 是 0 到 1 的数字。",
				}, "\n"),
			},
			{
				Role:    "user",
				Content: "请优化下面的本地 AI 摘要，保留证据链和可执行处置建议：\n" + string(payloadJSON),
			},
		},
		Temperature: ai.Temperature,
		MaxTokens:   900,
	})
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(ai.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ai.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用模型网关失败：%w", err)
	}
	defer resp.Body.Close()
	var chat aiChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chat); err != nil {
		return nil, fmt.Errorf("解析模型响应失败：%w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(chat.Error.Message)
		if message == "" {
			message = resp.Status
		}
		return nil, fmt.Errorf("模型网关返回异常：%s", message)
	}
	if len(chat.Choices) == 0 || strings.TrimSpace(chat.Choices[0].Message.Content) == "" {
		return nil, fmt.Errorf("模型网关未返回摘要内容")
	}
	var enhanced map[string]any
	if err := json.Unmarshal([]byte(extractJSONObject(chat.Choices[0].Message.Content)), &enhanced); err != nil {
		return nil, fmt.Errorf("模型摘要不是合法 JSON：%w", err)
	}
	return enhanced, nil
}

func mergeExternalAISummary(local, enhanced map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range local {
		result[key] = value
	}
	if summary := strings.TrimSpace(stringValue(enhanced["summary"])); summary != "" {
		result["summary"] = summary
	}
	if findings := stringListValue(enhanced["findings"], 8); len(findings) > 0 {
		result["findings"] = findings
	}
	if actions := stringListValue(enhanced["actions"], 8); len(actions) > 0 {
		result["actions"] = actions
	}
	if evidence := stringListValue(enhanced["evidence"], 8); len(evidence) > 0 {
		result["model_evidence"] = evidence
	}
	if confidence := float64Value(enhanced["confidence"]); confidence > 0 {
		if confidence > 1 {
			confidence = 1
		}
		result["confidence"] = confidence
	}
	result["ai_generated"] = true
	result["provider_status"] = "external"
	return result
}

func stringListValue(value any, limit int) []string {
	items := sliceValue(value)
	if len(items) == 0 {
		return []string{}
	}
	out := []string{}
	for _, item := range items {
		text := strings.TrimSpace(stringValue(item))
		if text == "" {
			continue
		}
		out = append(out, text)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func extractJSONObject(content string) string {
	text := strings.TrimSpace(content)
	if strings.HasPrefix(text, "```") {
		text = strings.TrimPrefix(text, "```json")
		text = strings.TrimPrefix(text, "```")
		text = strings.TrimSuffix(text, "```")
		text = strings.TrimSpace(text)
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return text[start : end+1]
	}
	return text
}
