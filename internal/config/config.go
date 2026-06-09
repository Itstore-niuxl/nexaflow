package config

import (
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"strings"
	"time"

	"nexaflow/internal/model"
)

type Config struct {
	APIAddr              string
	Mode                 string
	SourceID             string
	CollectorID          string
	Iface                string
	Window               time.Duration
	SessionTopN          int
	RedisAddr            string
	ClickHouseURL        string
	Database             string
	BandwidthMbps        uint64
	BPFFilter            string
	PcapFile             string
	ReplaySpeed          float64
	RuntimePath          string
	HostNetPath          string
	AuthPassword         string
	AuthReadOnlyPassword string
	AuthSecret           string
	AIMode               string
	AIProvider           string
	AIModel              string
	AIBaseURL            string
	AIAPIKey             string
	AIMaxContextRows     int
}

type SystemSettings struct {
	AI           AISettings           `json:"ai"`
	Analysis     AnalysisSettings     `json:"analysis"`
	Security     SecuritySettings     `json:"security"`
	Notification NotificationSettings `json:"notification"`
	Data         DataSettings         `json:"data"`
	Backend      BackendSettings      `json:"backend"`
	UpdatedAt    int64                `json:"updated_at"`
}

type AISettings struct {
	Mode             string  `json:"mode"`
	Provider         string  `json:"provider"`
	Model            string  `json:"model"`
	BaseURL          string  `json:"base_url"`
	APIKey           string  `json:"api_key,omitempty"`
	MaxContextRows   int     `json:"max_context_rows"`
	TimeoutSeconds   int     `json:"timeout_seconds"`
	Temperature      float64 `json:"temperature"`
	EnabledSummaries bool    `json:"enabled_summaries"`
}

type AnalysisSettings struct {
	DefaultMinutes            int     `json:"default_minutes"`
	BaselineMinutes           int     `json:"baseline_minutes"`
	BaselineDeviationWarning  float64 `json:"baseline_deviation_warning"`
	BaselineDeviationCritical float64 `json:"baseline_deviation_critical"`
	BaselineMinBytes          uint64  `json:"baseline_min_bytes"`
	BandwidthMbps             uint64  `json:"bandwidth_mbps"`
	ReportDefaultMinutes      int     `json:"report_default_minutes"`
}

type SecuritySettings struct {
	AuthEnabled          bool           `json:"auth_enabled"`
	ReadOnlyEnabled      bool           `json:"readonly_enabled"`
	AdminPassword        string         `json:"admin_password,omitempty"`
	ReadOnlyPassword     string         `json:"readonly_password,omitempty"`
	Users                []UserAccount  `json:"users,omitempty"`
	Sessions             []AuthSession  `json:"sessions,omitempty"`
	SessionTTLHours      int            `json:"session_ttl_hours"`
	MaxLoginFailures     int            `json:"max_login_failures"`
	LockoutMinutes       int            `json:"lockout_minutes"`
	PasswordPolicy       PasswordPolicy `json:"password_policy"`
	RequireAuditForWrite bool           `json:"require_audit_for_write"`
	AllowFrontendSecrets bool           `json:"allow_frontend_secrets"`
}

type PasswordPolicy struct {
	MinLength             int  `json:"min_length"`
	RequireUppercase      bool `json:"require_uppercase"`
	RequireLowercase      bool `json:"require_lowercase"`
	RequireNumber         bool `json:"require_number"`
	RequireSpecial        bool `json:"require_special"`
	ExpireDays            int  `json:"expire_days"`
	PreventUsernameInPass bool `json:"prevent_username_in_password"`
}

type AuthSession struct {
	ID          string `json:"id"`
	Actor       string `json:"actor"`
	Role        string `json:"role"`
	AuthVersion int    `json:"auth_version,omitempty"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
	ClientIP    string `json:"client_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	RevokedAt   int64  `json:"revoked_at,omitempty"`
}

type UserAccount struct {
	Username          string `json:"username"`
	DisplayName       string `json:"display_name"`
	Role              string `json:"role"`
	Status            string `json:"status"`
	PasswordHash      string `json:"password_hash,omitempty"`
	AuthVersion       int    `json:"auth_version,omitempty"`
	PasswordChangedAt int64  `json:"password_changed_at,omitempty"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
	LastLoginAt       int64  `json:"last_login_at,omitempty"`
	FailedLogins      int    `json:"failed_logins,omitempty"`
	LockedUntil       int64  `json:"locked_until,omitempty"`
}

type NotificationSettings struct {
	Enabled          bool     `json:"enabled"`
	Provider         string   `json:"provider"`
	WebhookURL       string   `json:"webhook_url"`
	WebhookToken     string   `json:"webhook_token,omitempty"`
	MinSeverity      string   `json:"min_severity"`
	NotifyOnIncident bool     `json:"notify_on_incident"`
	NotifyOnReport   bool     `json:"notify_on_report"`
	Channels         []string `json:"channels"`
}

type DataSettings struct {
	ClickHouseRetentionDays int  `json:"clickhouse_retention_days"`
	AuditRetentionDays      int  `json:"audit_retention_days"`
	ConfigVersionLimit      int  `json:"config_version_limit"`
	SessionRetentionDays    int  `json:"session_retention_days"`
	ExportEnabled           bool `json:"export_enabled"`
}

type BackendSettings struct {
	APIAddr         string `json:"api_addr"`
	ClickHouseURL   string `json:"clickhouse_url"`
	RedisAddr       string `json:"redis_addr"`
	Database        string `json:"database"`
	RequiresRestart bool   `json:"requires_restart"`
}

type CaptureRuntime struct {
	Mode        string  `json:"mode"`
	Iface       string  `json:"iface"`
	SourceID    string  `json:"source_id"`
	BPFFilter   string  `json:"bpf_filter"`
	PcapFile    string  `json:"pcap_file"`
	ReplaySpeed float64 `json:"replay_speed"`
	SessionTopN int     `json:"session_topn"`
	Alerts      Alerts  `json:"alerts"`
	UpdatedAt   int64   `json:"updated_at"`
}

type Alerts struct {
	FlowBytes        uint64                `json:"flow_bytes"`
	FlowShare        float64               `json:"flow_share"`
	SourcePackets    uint64                `json:"source_packets"`
	LinkUtilization  float64               `json:"link_utilization"`
	SilencedSubjects []string              `json:"silenced_subjects"`
	DetectionRules   []model.DetectionRule `json:"detection_rules"`
}

func Load() Config {
	cfg := Config{
		APIAddr:              env("NEXAFLOW_API_ADDR", "0.0.0.0:8080"),
		Mode:                 env("NEXAFLOW_MODE", "mock"),
		SourceID:             env("NEXAFLOW_SOURCE_ID", "dev-source-01"),
		CollectorID:          env("NEXAFLOW_COLLECTOR_ID", "dev-collector-01"),
		Iface:                env("NEXAFLOW_IFACE", "mock0"),
		Window:               envDuration("NEXAFLOW_WINDOW", 5*time.Second),
		SessionTopN:          envInt("NEXAFLOW_SESSION_TOPN", 500),
		RedisAddr:            env("NEXAFLOW_REDIS_ADDR", "127.0.0.1:6379"),
		ClickHouseURL:        env("NEXAFLOW_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
		Database:             env("NEXAFLOW_CLICKHOUSE_DB", "nexaflow"),
		BandwidthMbps:        envUint64("NEXAFLOW_BANDWIDTH_MBPS", 1000),
		BPFFilter:            env("NEXAFLOW_BPF_FILTER", "ip or ip6"),
		PcapFile:             env("NEXAFLOW_PCAP_FILE", "/var/lib/nexaflow/replay.pcap"),
		ReplaySpeed:          envFloat64("NEXAFLOW_REPLAY_SPEED", 1),
		RuntimePath:          env("NEXAFLOW_RUNTIME_CONFIG", "/var/lib/nexaflow/collector_config.json"),
		HostNetPath:          env("NEXAFLOW_HOST_NET_PATH", "/host/sys/class/net"),
		AuthPassword:         env("NEXAFLOW_AUTH_PASSWORD", ""),
		AuthReadOnlyPassword: env("NEXAFLOW_AUTH_READONLY_PASSWORD", ""),
		AuthSecret:           env("NEXAFLOW_AUTH_SECRET", ""),
		AIMode:               env("NEXAFLOW_AI_MODE", "local_mock"),
		AIProvider:           env("NEXAFLOW_AI_PROVIDER", "local_mock"),
		AIModel:              env("NEXAFLOW_AI_MODEL", "nexaflow-local-summary"),
		AIBaseURL:            env("NEXAFLOW_AI_BASE_URL", ""),
		AIAPIKey:             env("NEXAFLOW_AI_API_KEY", ""),
		AIMaxContextRows:     envInt("NEXAFLOW_AI_MAX_CONTEXT_ROWS", 12),
	}

	flag.StringVar(&cfg.APIAddr, "api-addr", cfg.APIAddr, "API listen address")
	flag.StringVar(&cfg.Mode, "mode", cfg.Mode, "collector mode: mock")
	flag.StringVar(&cfg.SourceID, "source-id", cfg.SourceID, "capture source id")
	flag.StringVar(&cfg.CollectorID, "collector-id", cfg.CollectorID, "collector id")
	flag.StringVar(&cfg.Iface, "interface", cfg.Iface, "capture interface name")
	flag.IntVar(&cfg.SessionTopN, "session-topn", cfg.SessionTopN, "session and pair rows kept per aggregation window")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", cfg.RedisAddr, "Redis address")
	flag.StringVar(&cfg.ClickHouseURL, "clickhouse-url", cfg.ClickHouseURL, "ClickHouse HTTP URL")
	flag.StringVar(&cfg.Database, "clickhouse-db", cfg.Database, "ClickHouse database")
	flag.StringVar(&cfg.BPFFilter, "bpf-filter", cfg.BPFFilter, "BPF filter for live pcap mode")
	flag.StringVar(&cfg.PcapFile, "pcap-file", cfg.PcapFile, "pcap file for pcap_replay mode")
	flag.StringVar(&cfg.RuntimePath, "runtime-config", cfg.RuntimePath, "collector runtime config path")
	flag.StringVar(&cfg.AuthPassword, "auth-password", cfg.AuthPassword, "optional console login password")
	flag.StringVar(&cfg.AuthReadOnlyPassword, "auth-readonly-password", cfg.AuthReadOnlyPassword, "optional read-only console login password")
	flag.StringVar(&cfg.AuthSecret, "auth-secret", cfg.AuthSecret, "optional session signing secret")
	flag.StringVar(&cfg.AIMode, "ai-mode", cfg.AIMode, "AI mode: disabled, local_mock, openai")
	flag.StringVar(&cfg.AIProvider, "ai-provider", cfg.AIProvider, "AI provider name")
	flag.StringVar(&cfg.AIModel, "ai-model", cfg.AIModel, "AI model name")
	flag.StringVar(&cfg.AIBaseURL, "ai-base-url", cfg.AIBaseURL, "AI provider base URL")
	flag.StringVar(&cfg.AIAPIKey, "ai-api-key", cfg.AIAPIKey, "AI provider API key")
	flag.IntVar(&cfg.AIMaxContextRows, "ai-max-context-rows", cfg.AIMaxContextRows, "maximum rows included in AI context")
	flag.Uint64Var(&cfg.BandwidthMbps, "bandwidth-mbps", cfg.BandwidthMbps, "link bandwidth in Mbps")
	flag.Float64Var(&cfg.ReplaySpeed, "replay-speed", cfg.ReplaySpeed, "pcap replay speed multiplier")
	flag.Parse()

	return cfg
}

func DefaultRuntime(cfg Config) CaptureRuntime {
	sourceID := cfg.SourceID
	if sourceID == "" || sourceID == "dev-source-01" || sourceID == "live-eth0" {
		sourceID = cfg.Mode + "-" + cfg.Iface
	}
	return CaptureRuntime{
		Mode:        cfg.Mode,
		Iface:       cfg.Iface,
		SourceID:    sourceID,
		BPFFilter:   cfg.BPFFilter,
		PcapFile:    cfg.PcapFile,
		ReplaySpeed: cfg.ReplaySpeed,
		SessionTopN: cfg.SessionTopN,
		Alerts:      defaultAlerts(),
		UpdatedAt:   time.Now().Unix(),
	}
}

func LoadRuntime(path string, fallback CaptureRuntime) CaptureRuntime {
	data, err := os.ReadFile(path)
	if err != nil {
		return normalizeRuntime(fallback)
	}
	var runtime CaptureRuntime
	if err := json.Unmarshal(data, &runtime); err != nil {
		return normalizeRuntime(fallback)
	}
	return normalizeRuntime(runtime)
}

func SaveRuntime(path string, runtime CaptureRuntime) error {
	runtime = normalizeRuntime(runtime)
	runtime.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(runtime, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func SystemSettingsPath(runtimePath string) string {
	return dir(runtimePath) + "/system_settings.json"
}

func DefaultSystemSettings(cfg Config) SystemSettings {
	return normalizeSystemSettings(SystemSettings{
		AI: AISettings{
			Mode:             cfg.AIMode,
			Provider:         cfg.AIProvider,
			Model:            cfg.AIModel,
			BaseURL:          cfg.AIBaseURL,
			APIKey:           cfg.AIAPIKey,
			MaxContextRows:   cfg.AIMaxContextRows,
			TimeoutSeconds:   30,
			Temperature:      0.2,
			EnabledSummaries: cfg.AIMode != "disabled",
		},
		Analysis: AnalysisSettings{
			DefaultMinutes:            15,
			BaselineMinutes:           120,
			BaselineDeviationWarning:  1.8,
			BaselineDeviationCritical: 3.0,
			BaselineMinBytes:          1024 * 1024,
			BandwidthMbps:             cfg.BandwidthMbps,
			ReportDefaultMinutes:      60,
		},
		Security: SecuritySettings{
			AuthEnabled:      strings.TrimSpace(cfg.AuthPassword) != "" || strings.TrimSpace(cfg.AuthReadOnlyPassword) != "",
			ReadOnlyEnabled:  strings.TrimSpace(cfg.AuthReadOnlyPassword) != "",
			AdminPassword:    cfg.AuthPassword,
			ReadOnlyPassword: cfg.AuthReadOnlyPassword,
			SessionTTLHours:  12,
			MaxLoginFailures: 5,
			LockoutMinutes:   15,
			PasswordPolicy: PasswordPolicy{
				MinLength:             8,
				RequireUppercase:      false,
				RequireLowercase:      false,
				RequireNumber:         true,
				RequireSpecial:        false,
				ExpireDays:            0,
				PreventUsernameInPass: true,
			},
			RequireAuditForWrite: true,
			AllowFrontendSecrets: true,
		},
		Notification: NotificationSettings{
			Enabled:          false,
			Provider:         "webhook",
			MinSeverity:      "critical",
			NotifyOnIncident: true,
			NotifyOnReport:   false,
			Channels:         []string{},
		},
		Data: DataSettings{
			ClickHouseRetentionDays: 30,
			AuditRetentionDays:      180,
			ConfigVersionLimit:      200,
			SessionRetentionDays:    30,
			ExportEnabled:           true,
		},
		Backend: BackendSettings{
			APIAddr:         cfg.APIAddr,
			ClickHouseURL:   cfg.ClickHouseURL,
			RedisAddr:       cfg.RedisAddr,
			Database:        cfg.Database,
			RequiresRestart: true,
		},
		UpdatedAt: time.Now().Unix(),
	})
}

func LoadSystemSettings(path string, fallback SystemSettings) SystemSettings {
	data, err := os.ReadFile(path)
	if err != nil {
		return normalizeSystemSettings(fallback)
	}
	var settings SystemSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return normalizeSystemSettings(fallback)
	}
	settings = mergeSystemSettings(normalizeSystemSettings(fallback), settings)
	return normalizeSystemSettings(settings)
}

func SaveSystemSettings(path string, settings SystemSettings) error {
	settings = normalizeSystemSettings(settings)
	settings.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizeRuntime(runtime CaptureRuntime) CaptureRuntime {
	if runtime.Mode == "" {
		runtime.Mode = "live_pcap"
	}
	if runtime.Iface == "" {
		runtime.Iface = "eth0"
	}
	if runtime.SourceID == "" {
		runtime.SourceID = runtime.Mode + "-" + runtime.Iface
	}
	if runtime.BPFFilter == "" {
		runtime.BPFFilter = "ip or ip6"
	}
	if runtime.PcapFile == "" {
		runtime.PcapFile = "/var/lib/nexaflow/replay.pcap"
	}
	if runtime.ReplaySpeed <= 0 {
		runtime.ReplaySpeed = 1
	}
	runtime.SessionTopN = normalizeSessionTopN(runtime.SessionTopN)
	runtime.Alerts = normalizeAlerts(runtime.Alerts)
	return runtime
}

func mergeSystemSettings(fallback, settings SystemSettings) SystemSettings {
	if settings.AI.Mode == "" {
		settings.AI = fallback.AI
	} else {
		if settings.AI.Provider == "" {
			settings.AI.Provider = fallback.AI.Provider
		}
		if settings.AI.Model == "" {
			settings.AI.Model = fallback.AI.Model
		}
		if settings.AI.APIKey == "" {
			settings.AI.APIKey = fallback.AI.APIKey
		}
	}
	if settings.Analysis.DefaultMinutes == 0 {
		settings.Analysis = fallback.Analysis
	}
	if settings.Security.SessionTTLHours == 0 {
		settings.Security = fallback.Security
	}
	if settings.Notification.Provider == "" {
		settings.Notification = fallback.Notification
	}
	if settings.Data.ClickHouseRetentionDays == 0 {
		settings.Data = fallback.Data
	}
	if settings.Backend.APIAddr == "" {
		settings.Backend = fallback.Backend
	}
	return settings
}

func normalizeSystemSettings(settings SystemSettings) SystemSettings {
	settings.AI.Mode = normalizeAIMode(settings.AI.Mode)
	if settings.AI.Provider == "" {
		settings.AI.Provider = settings.AI.Mode
	}
	if settings.AI.Model == "" {
		settings.AI.Model = "nexaflow-local-summary"
	}
	if settings.AI.MaxContextRows <= 0 {
		settings.AI.MaxContextRows = 12
	}
	if settings.AI.MaxContextRows > 200 {
		settings.AI.MaxContextRows = 200
	}
	if settings.AI.TimeoutSeconds <= 0 {
		settings.AI.TimeoutSeconds = 30
	}
	if settings.AI.TimeoutSeconds > 120 {
		settings.AI.TimeoutSeconds = 120
	}
	if settings.AI.Temperature < 0 {
		settings.AI.Temperature = 0
	}
	if settings.AI.Temperature > 2 {
		settings.AI.Temperature = 2
	}
	if settings.AI.Mode == "disabled" {
		settings.AI.EnabledSummaries = false
	}
	settings.Analysis.DefaultMinutes = normalizeMinutes(settings.Analysis.DefaultMinutes, 15)
	settings.Analysis.BaselineMinutes = normalizeMinutes(settings.Analysis.BaselineMinutes, 120)
	if settings.Analysis.BaselineMinutes < settings.Analysis.DefaultMinutes*2 {
		settings.Analysis.BaselineMinutes = settings.Analysis.DefaultMinutes * 8
	}
	if settings.Analysis.BaselineDeviationWarning <= 1 {
		settings.Analysis.BaselineDeviationWarning = 1.8
	}
	if settings.Analysis.BaselineDeviationCritical <= settings.Analysis.BaselineDeviationWarning {
		settings.Analysis.BaselineDeviationCritical = 3.0
	}
	if settings.Analysis.BaselineMinBytes == 0 {
		settings.Analysis.BaselineMinBytes = 1024 * 1024
	}
	if settings.Analysis.BandwidthMbps == 0 {
		settings.Analysis.BandwidthMbps = 1000
	}
	settings.Analysis.ReportDefaultMinutes = normalizeMinutes(settings.Analysis.ReportDefaultMinutes, 60)
	if settings.Security.SessionTTLHours <= 0 {
		settings.Security.SessionTTLHours = 12
	}
	if settings.Security.SessionTTLHours > 168 {
		settings.Security.SessionTTLHours = 168
	}
	if settings.Security.MaxLoginFailures <= 0 {
		settings.Security.MaxLoginFailures = 5
	}
	if settings.Security.MaxLoginFailures > 20 {
		settings.Security.MaxLoginFailures = 20
	}
	if settings.Security.LockoutMinutes <= 0 {
		settings.Security.LockoutMinutes = 15
	}
	if settings.Security.LockoutMinutes > 1440 {
		settings.Security.LockoutMinutes = 1440
	}
	settings.Security.PasswordPolicy = normalizePasswordPolicy(settings.Security.PasswordPolicy)
	settings.Security.Users = normalizeUserAccounts(settings.Security.Users)
	settings.Security.Sessions = normalizeAuthSessions(settings.Security.Sessions)
	if !settings.Security.AuthEnabled {
		settings.Security.ReadOnlyEnabled = false
	}
	if !settings.Notification.Enabled {
		settings.Notification.NotifyOnIncident = false
		settings.Notification.NotifyOnReport = false
	}
	if settings.Notification.Provider == "" {
		settings.Notification.Provider = "webhook"
	}
	if settings.Notification.MinSeverity == "" {
		settings.Notification.MinSeverity = "critical"
	}
	if settings.Notification.Channels == nil {
		settings.Notification.Channels = []string{}
	}
	if settings.Data.ClickHouseRetentionDays <= 0 {
		settings.Data.ClickHouseRetentionDays = 30
	}
	if settings.Data.AuditRetentionDays <= 0 {
		settings.Data.AuditRetentionDays = 180
	}
	if settings.Data.ConfigVersionLimit <= 0 {
		settings.Data.ConfigVersionLimit = 200
	}
	if settings.Data.SessionRetentionDays <= 0 {
		settings.Data.SessionRetentionDays = 30
	}
	settings.Backend.RequiresRestart = true
	return settings
}

func normalizeAuthSessions(sessions []AuthSession) []AuthSession {
	if sessions == nil {
		return nil
	}
	now := time.Now().Unix()
	cutoff := now - 30*24*60*60
	seen := map[string]bool{}
	normalized := []AuthSession{}
	for _, session := range sessions {
		session.ID = strings.TrimSpace(session.ID)
		session.Actor = strings.TrimSpace(session.Actor)
		session.Role = NormalizeUserRole(session.Role)
		if session.ID == "" || session.Actor == "" || seen[session.ID] {
			continue
		}
		seen[session.ID] = true
		if session.IssuedAt <= 0 {
			session.IssuedAt = now
		}
		if session.LastSeenAt <= 0 {
			session.LastSeenAt = session.IssuedAt
		}
		if session.ExpiresAt <= 0 {
			session.ExpiresAt = session.IssuedAt + 12*60*60
		}
		if session.ExpiresAt < cutoff || (session.RevokedAt > 0 && session.RevokedAt < cutoff) {
			continue
		}
		normalized = append(normalized, session)
	}
	if len(normalized) > 200 {
		normalized = normalized[len(normalized)-200:]
	}
	return normalized
}

func normalizePasswordPolicy(policy PasswordPolicy) PasswordPolicy {
	if policy.MinLength == 0 && !policy.RequireUppercase && !policy.RequireLowercase && !policy.RequireNumber && !policy.RequireSpecial && policy.ExpireDays == 0 && !policy.PreventUsernameInPass {
		return PasswordPolicy{
			MinLength:             8,
			RequireNumber:         true,
			PreventUsernameInPass: true,
		}
	}
	if policy.MinLength <= 0 {
		policy.MinLength = 8
	}
	if policy.MinLength < 6 {
		policy.MinLength = 6
	}
	if policy.MinLength > 128 {
		policy.MinLength = 128
	}
	if policy.ExpireDays < 0 {
		policy.ExpireDays = 0
	}
	if policy.ExpireDays > 3650 {
		policy.ExpireDays = 3650
	}
	return policy
}

func normalizeUserAccounts(users []UserAccount) []UserAccount {
	if users == nil {
		return nil
	}
	now := time.Now().Unix()
	seen := map[string]bool{}
	normalized := []UserAccount{}
	for _, user := range users {
		user.Username = strings.TrimSpace(user.Username)
		if user.Username == "" || seen[user.Username] {
			continue
		}
		seen[user.Username] = true
		user.DisplayName = strings.TrimSpace(user.DisplayName)
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		user.Role = NormalizeUserRole(user.Role)
		user.Status = NormalizeUserStatus(user.Status)
		if strings.TrimSpace(user.PasswordHash) != "" && user.AuthVersion <= 0 {
			user.AuthVersion = 1
		}
		if user.CreatedAt <= 0 {
			user.CreatedAt = now
		}
		if user.UpdatedAt <= 0 {
			user.UpdatedAt = user.CreatedAt
		}
		if strings.TrimSpace(user.PasswordHash) != "" && user.PasswordChangedAt <= 0 {
			user.PasswordChangedAt = user.UpdatedAt
			if user.PasswordChangedAt <= 0 {
				user.PasswordChangedAt = now
			}
		}
		normalized = append(normalized, user)
	}
	return normalized
}

func NormalizeUserRole(role string) string {
	switch strings.TrimSpace(strings.ToLower(role)) {
	case "admin", "analyst", "auditor", "viewer":
		return strings.TrimSpace(strings.ToLower(role))
	default:
		return "viewer"
	}
}

func NormalizeUserStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "disabled":
		return "disabled"
	default:
		return "active"
	}
}

func normalizeAIMode(mode string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "disabled", "local_mock", "openai":
		return strings.TrimSpace(strings.ToLower(mode))
	default:
		return "local_mock"
	}
}

func normalizeMinutes(value, fallback int) int {
	switch {
	case value < 5:
		return fallback
	case value > 10080:
		return 10080
	default:
		return value
	}
}

func normalizeSessionTopN(limit int) int {
	switch {
	case limit <= 0:
		return 500
	case limit < 20:
		return 20
	case limit > 5000:
		return 5000
	default:
		return limit
	}
}

func defaultAlerts() Alerts {
	return Alerts{
		FlowBytes:       20 * 1024,
		FlowShare:       0.30,
		SourcePackets:   50,
		LinkUtilization: 0.80,
		DetectionRules: []model.DetectionRule{
			{
				ID:                "rule-src-heavy-bytes",
				Name:              "源 IP 大流量",
				Category:          "流量阈值",
				Metric:            "src_ip_bytes",
				Operator:          "gte",
				Threshold:         100 * 1024 * 1024,
				Severity:          "warning",
				Enabled:           true,
				Description:       "识别观察窗口内单个源 IP 的大流量行为",
				RecommendedAction: "确认源主机业务用途，检查是否存在备份、同步或异常外传行为",
			},
			{
				ID:                "rule-external-session-burst",
				Name:              "公网会话突增",
				Category:          "公网访问",
				Metric:            "external_sessions",
				Operator:          "gte",
				Threshold:         30,
				Severity:          "critical",
				Enabled:           true,
				Description:       "识别公网对端和内部资产之间的高会话数访问",
				RecommendedAction: "核对公网来源、服务端口和防火墙策略，必要时收敛来源或加入白名单",
			},
			{
				ID:                "rule-peak-throughput",
				Name:              "峰值吞吐过高",
				Category:          "链路健康",
				Metric:            "link_peak_mbps",
				Operator:          "gte",
				Threshold:         80,
				Severity:          "warning",
				Enabled:           true,
				Description:       "识别观察窗口内链路峰值吞吐过高的情况",
				RecommendedAction: "结合历史回放和 TopN 对象定位峰值来源，确认是否需要扩容或限速",
			},
		},
	}
}

func normalizeAlerts(alerts Alerts) Alerts {
	defaults := defaultAlerts()
	if alerts.FlowBytes == 0 {
		alerts.FlowBytes = defaults.FlowBytes
	}
	if alerts.FlowShare <= 0 {
		alerts.FlowShare = defaults.FlowShare
	}
	if alerts.SourcePackets == 0 {
		alerts.SourcePackets = defaults.SourcePackets
	}
	if alerts.LinkUtilization <= 0 {
		alerts.LinkUtilization = defaults.LinkUtilization
	}
	alerts.SilencedSubjects = normalizeSilencedSubjects(alerts.SilencedSubjects)
	alerts.DetectionRules = normalizeDetectionRules(alerts.DetectionRules, defaults.DetectionRules)
	return alerts
}

func normalizeDetectionRules(rules, fallback []model.DetectionRule) []model.DetectionRule {
	if len(rules) == 0 {
		rules = fallback
	}
	seen := map[string]bool{}
	result := []model.DetectionRule{}
	for _, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Category = strings.TrimSpace(rule.Category)
		rule.Metric = strings.TrimSpace(rule.Metric)
		rule.Match = strings.TrimSpace(rule.Match)
		rule.Operator = strings.TrimSpace(rule.Operator)
		rule.Severity = strings.TrimSpace(rule.Severity)
		rule.Description = strings.TrimSpace(rule.Description)
		rule.RecommendedAction = strings.TrimSpace(rule.RecommendedAction)
		if rule.ID == "" {
			rule.ID = "rule-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		if seen[rule.ID] || rule.Name == "" || rule.Metric == "" || rule.Threshold <= 0 {
			continue
		}
		if rule.Operator == "" {
			rule.Operator = "gte"
		}
		if rule.Severity == "" {
			rule.Severity = "warning"
		}
		if rule.Category == "" {
			rule.Category = "自定义检测"
		}
		if rule.RecommendedAction == "" {
			rule.RecommendedAction = "确认命中对象的业务用途、访问来源和近期变更背景"
		}
		seen[rule.ID] = true
		result = append(result, rule)
	}
	return result
}

func normalizeSilencedSubjects(subjects []string) []string {
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

func dir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func envUint64(key string, fallback uint64) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envFloat64(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return fallback
}
