package config

import (
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"time"
)

type Config struct {
	APIAddr       string
	Mode          string
	SourceID      string
	CollectorID   string
	Iface         string
	Window        time.Duration
	RedisAddr     string
	ClickHouseURL string
	Database      string
	BandwidthMbps uint64
	BPFFilter     string
	RuntimePath   string
	HostNetPath   string
}

type CaptureRuntime struct {
	Mode      string `json:"mode"`
	Iface     string `json:"iface"`
	SourceID  string `json:"source_id"`
	BPFFilter string `json:"bpf_filter"`
	Alerts    Alerts `json:"alerts"`
	UpdatedAt int64  `json:"updated_at"`
}

type Alerts struct {
	FlowBytes       uint64  `json:"flow_bytes"`
	FlowShare       float64 `json:"flow_share"`
	SourcePackets   uint64  `json:"source_packets"`
	LinkUtilization float64 `json:"link_utilization"`
}

func Load() Config {
	cfg := Config{
		APIAddr:       env("NEXAFLOW_API_ADDR", "0.0.0.0:8080"),
		Mode:          env("NEXAFLOW_MODE", "mock"),
		SourceID:      env("NEXAFLOW_SOURCE_ID", "dev-source-01"),
		CollectorID:   env("NEXAFLOW_COLLECTOR_ID", "dev-collector-01"),
		Iface:         env("NEXAFLOW_IFACE", "mock0"),
		Window:        envDuration("NEXAFLOW_WINDOW", 5*time.Second),
		RedisAddr:     env("NEXAFLOW_REDIS_ADDR", "127.0.0.1:6379"),
		ClickHouseURL: env("NEXAFLOW_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
		Database:      env("NEXAFLOW_CLICKHOUSE_DB", "nexaflow"),
		BandwidthMbps: envUint64("NEXAFLOW_BANDWIDTH_MBPS", 1000),
		BPFFilter:     env("NEXAFLOW_BPF_FILTER", "ip or ip6"),
		RuntimePath:   env("NEXAFLOW_RUNTIME_CONFIG", "/var/lib/nexaflow/collector_config.json"),
		HostNetPath:   env("NEXAFLOW_HOST_NET_PATH", "/host/sys/class/net"),
	}

	flag.StringVar(&cfg.APIAddr, "api-addr", cfg.APIAddr, "API listen address")
	flag.StringVar(&cfg.Mode, "mode", cfg.Mode, "collector mode: mock")
	flag.StringVar(&cfg.SourceID, "source-id", cfg.SourceID, "capture source id")
	flag.StringVar(&cfg.CollectorID, "collector-id", cfg.CollectorID, "collector id")
	flag.StringVar(&cfg.Iface, "interface", cfg.Iface, "capture interface name")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", cfg.RedisAddr, "Redis address")
	flag.StringVar(&cfg.ClickHouseURL, "clickhouse-url", cfg.ClickHouseURL, "ClickHouse HTTP URL")
	flag.StringVar(&cfg.Database, "clickhouse-db", cfg.Database, "ClickHouse database")
	flag.StringVar(&cfg.BPFFilter, "bpf-filter", cfg.BPFFilter, "BPF filter for live pcap mode")
	flag.StringVar(&cfg.RuntimePath, "runtime-config", cfg.RuntimePath, "collector runtime config path")
	flag.Uint64Var(&cfg.BandwidthMbps, "bandwidth-mbps", cfg.BandwidthMbps, "link bandwidth in Mbps")
	flag.Parse()

	return cfg
}

func DefaultRuntime(cfg Config) CaptureRuntime {
	sourceID := cfg.SourceID
	if sourceID == "" || sourceID == "dev-source-01" || sourceID == "live-eth0" {
		sourceID = cfg.Mode + "-" + cfg.Iface
	}
	return CaptureRuntime{
		Mode:      cfg.Mode,
		Iface:     cfg.Iface,
		SourceID:  sourceID,
		BPFFilter: cfg.BPFFilter,
		Alerts:    defaultAlerts(),
		UpdatedAt: time.Now().Unix(),
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
	runtime.Alerts = normalizeAlerts(runtime.Alerts)
	return runtime
}

func defaultAlerts() Alerts {
	return Alerts{
		FlowBytes:       20 * 1024,
		FlowShare:       0.30,
		SourcePackets:   50,
		LinkUtilization: 0.80,
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
	return alerts
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
