package api

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nexaflow/internal/config"
	"nexaflow/internal/model"
)

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

func buildAICaptureDiagnosticsSummary(options aiSummaryOptions, report map[string]any) map[string]any {
	status := firstString(stringValue(report["status"]), "unknown")
	minutes := int64Value(report["minutes"])
	summary := mapValue(report["summary"])
	layers := sliceValue(report["layers"])
	recommendations := sliceValue(report["recommendations"])
	critical := int64Value(summary["critical_layers"])
	warning := int64Value(summary["warning_layers"])
	findings := []string{
		fmt.Sprintf("近 %d 分钟采集链路状态为 %s，检查 %d 个层级。", minutes, aiDataQualityStatusText(status), int64Value(summary["layer_count"])),
		fmt.Sprintf("诊断发现严重层 %d 个、警告层 %d 个。", critical, warning),
	}
	evidence := []string{
		"总体状态：" + aiDataQualityStatusText(status),
		"严重层数：" + strconv.FormatInt(critical, 10),
		"警告层数：" + strconv.FormatInt(warning, 10),
	}
	for _, raw := range layers {
		layer := mapValue(raw)
		layerStatus := stringValue(layer["status"])
		if layerStatus != "healthy" {
			findings = append(findings, fmt.Sprintf("%s 状态为 %s，指标：%s。", stringValue(layer["name"]), aiDataQualityStatusText(layerStatus), firstString(stringValue(layer["metric"]), "-")))
			evidence = append(evidence, stringValue(layer["name"])+"："+firstString(stringValue(layer["detail"]), "-"))
		}
	}
	actions := []string{}
	for _, raw := range recommendations {
		row := mapValue(raw)
		if detail := strings.TrimSpace(stringValue(row["detail"])); detail != "" {
			actions = append(actions, detail)
		}
	}
	if len(actions) == 0 {
		actions = append(actions, "保持采集器在线，持续观察网卡计数、队列压力、窗口新鲜度和覆盖率。")
	}
	title := "AI 采集诊断摘要"
	lead := "当前采集链路整体稳定，可继续基于实时数据分析。"
	if critical > 0 {
		lead = "采集链路存在严重异常，建议优先处理影响实时性或数据完整性的层级。"
	} else if warning > 0 {
		lead = "采集链路存在警告项，建议结合分层诊断确认是否影响数据可信度。"
	}
	if !options.Enabled {
		return disabledAISummary(options, "capture_diagnostics", "collector")
	}
	return aiSummary(options, "capture_diagnostics", "collector", title, lead, confidenceByContext(len(layers)+len(recommendations)), findings, evidence, actions)
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

func aiDataQualityStatusText(status string) string {
	switch status {
	case "critical":
		return "严重"
	case "warning":
		return "警告"
	case "healthy":
		return "健康"
	default:
		return "未知"
	}
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
