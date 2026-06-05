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
	APIAddr       string
	Mode          string
	SourceID      string
	CollectorID   string
	Iface         string
	Window        time.Duration
	SessionTopN   int
	RedisAddr     string
	ClickHouseURL string
	Database      string
	BandwidthMbps uint64
	BPFFilter     string
	PcapFile      string
	ReplaySpeed   float64
	RuntimePath   string
	HostNetPath   string
	AuthPassword  string
	AuthSecret    string
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
		APIAddr:       env("NEXAFLOW_API_ADDR", "0.0.0.0:8080"),
		Mode:          env("NEXAFLOW_MODE", "mock"),
		SourceID:      env("NEXAFLOW_SOURCE_ID", "dev-source-01"),
		CollectorID:   env("NEXAFLOW_COLLECTOR_ID", "dev-collector-01"),
		Iface:         env("NEXAFLOW_IFACE", "mock0"),
		Window:        envDuration("NEXAFLOW_WINDOW", 5*time.Second),
		SessionTopN:   envInt("NEXAFLOW_SESSION_TOPN", 500),
		RedisAddr:     env("NEXAFLOW_REDIS_ADDR", "127.0.0.1:6379"),
		ClickHouseURL: env("NEXAFLOW_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
		Database:      env("NEXAFLOW_CLICKHOUSE_DB", "nexaflow"),
		BandwidthMbps: envUint64("NEXAFLOW_BANDWIDTH_MBPS", 1000),
		BPFFilter:     env("NEXAFLOW_BPF_FILTER", "ip or ip6"),
		PcapFile:      env("NEXAFLOW_PCAP_FILE", "/var/lib/nexaflow/replay.pcap"),
		ReplaySpeed:   envFloat64("NEXAFLOW_REPLAY_SPEED", 1),
		RuntimePath:   env("NEXAFLOW_RUNTIME_CONFIG", "/var/lib/nexaflow/collector_config.json"),
		HostNetPath:   env("NEXAFLOW_HOST_NET_PATH", "/host/sys/class/net"),
		AuthPassword:  env("NEXAFLOW_AUTH_PASSWORD", ""),
		AuthSecret:    env("NEXAFLOW_AUTH_SECRET", ""),
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
	flag.StringVar(&cfg.AuthSecret, "auth-secret", cfg.AuthSecret, "optional session signing secret")
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
