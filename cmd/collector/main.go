package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nexaflow/internal/aggregate"
	"nexaflow/internal/capture/mock"
	"nexaflow/internal/capture/pcap"
	"nexaflow/internal/capture/raw"
	"nexaflow/internal/config"
	"nexaflow/internal/model"
	"nexaflow/internal/storage/clickhouse"
	"nexaflow/internal/storage/redisstore"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ch := clickhouse.New(cfg.ClickHouseURL, cfg.Database)
	if err := ch.WaitInit(ctx, 30, 2*time.Second); err != nil {
		log.Printf("clickhouse init failed: %v", err)
	}
	redis := redisstore.New(cfg.RedisAddr)

	packets := make(chan model.PacketMeta, 10000)
	windows := make(chan model.WindowResult, 32)

	defaultRuntime := config.DefaultRuntime(cfg)
	if err := config.SaveRuntime(cfg.RuntimePath, config.LoadRuntime(cfg.RuntimePath, defaultRuntime)); err != nil {
		log.Printf("runtime config init failed: %v", err)
	}
	go runCaptureManager(ctx, cfg.RuntimePath, defaultRuntime, packets)
	aggregator := aggregate.New(cfg.Window, cfg.BandwidthMbps, func() config.Alerts {
		return config.LoadRuntime(cfg.RuntimePath, defaultRuntime).Alerts
	})
	aggregator.SessionLimit = func() int {
		return config.LoadRuntime(cfg.RuntimePath, defaultRuntime).SessionTopN
	}
	go aggregator.Run(packets, windows)

	captureStats := newInterfaceStatsTracker()
	log.Printf("collector started runtime_config=%s window=%s", cfg.RuntimePath, cfg.Window)
	for {
		select {
		case <-ctx.Done():
			log.Println("collector stopped")
			return
		case win := <-windows:
			captureStats.apply(&win, queueSnapshot{
				packetLen:      len(packets),
				packetCapacity: cap(packets),
				windowLen:      len(windows),
				windowCapacity: cap(windows),
			})
			if err := ch.WriteWindow(ctx, win); err != nil {
				log.Printf("clickhouse write failed: %v", err)
				if initErr := ch.Init(ctx); initErr != nil {
					log.Printf("clickhouse re-init failed: %v", initErr)
				}
			}
			if err := redis.WriteWindow(ctx, win); err != nil {
				log.Printf("redis write failed: %v", err)
			}
			log.Printf("window ts=%d bytes=%d packets=%d top_src=%d top_flow=%d", win.Ts, win.Link.Bytes, win.Link.Packets, len(win.TopSrcIP), len(win.TopFlow))
		}
	}
}

func runCaptureManager(ctx context.Context, path string, fallback config.CaptureRuntime, packets chan<- model.PacketMeta) {
	var active config.CaptureRuntime
	var cancel context.CancelFunc
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	start := func(runtime config.CaptureRuntime) {
		if cancel != nil {
			cancel()
		}
		captureCtx, stopCapture := context.WithCancel(ctx)
		cancel = stopCapture
		active = runtime
		log.Printf("capture switching mode=%s iface=%s source=%s", runtime.Mode, runtime.Iface, runtime.SourceID)
		go runCapture(captureCtx, runtime, packets)
	}

	start(config.LoadRuntime(path, fallback))
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
			}
			return
		case <-ticker.C:
			next := config.LoadRuntime(path, fallback)
			if next.Mode != active.Mode || next.Iface != active.Iface || next.SourceID != active.SourceID || next.BPFFilter != active.BPFFilter || next.PcapFile != active.PcapFile || next.ReplaySpeed != active.ReplaySpeed {
				start(next)
			}
		}
	}
}

func runCapture(ctx context.Context, runtime config.CaptureRuntime, packets chan<- model.PacketMeta) {
	switch runtime.Mode {
	case "mock":
		mock.New(runtime.SourceID, runtime.Iface).Run(ctx, packets)
	case "live_pcap":
		if err := raw.NewLive(runtime.SourceID, runtime.Iface, runtime.BPFFilter).Run(ctx, packets); err != nil && ctx.Err() == nil {
			log.Printf("live capture stopped: %v", err)
		}
	case "pcap_replay":
		if err := pcap.New(runtime.SourceID, runtime.Iface, runtime.PcapFile, runtime.ReplaySpeed, runtime.BPFFilter).Run(ctx, packets); err != nil && ctx.Err() == nil {
			log.Printf("pcap replay stopped: %v", err)
		}
	default:
		log.Printf("mode %q is not implemented, falling back to mock", runtime.Mode)
		mock.New(runtime.SourceID, runtime.Iface).Run(ctx, packets)
	}
}

type interfaceStats struct {
	rxBytes   uint64
	rxPackets uint64
	rxDropped uint64
	rxErrors  uint64
	txBytes   uint64
	txPackets uint64
	txDropped uint64
	txErrors  uint64
	known     bool
}

type interfaceStatsTracker struct {
	last map[string]interfaceStats
}

type queueSnapshot struct {
	packetLen      int
	packetCapacity int
	windowLen      int
	windowCapacity int
}

func newInterfaceStatsTracker() *interfaceStatsTracker {
	return &interfaceStatsTracker{last: map[string]interfaceStats{}}
}

func (t *interfaceStatsTracker) apply(win *model.WindowResult, queues queueSnapshot) {
	if win == nil {
		return
	}
	quality := model.CaptureQualityWindow{
		Ts:                  win.Ts,
		SourceID:            win.SourceID,
		Iface:               win.Iface,
		PacketQueueLen:      uint64(queues.packetLen),
		PacketQueueCapacity: uint64(queues.packetCapacity),
		WindowQueueLen:      uint64(queues.windowLen),
		WindowQueueCapacity: uint64(queues.windowCapacity),
	}
	if strings.TrimSpace(win.Iface) != "" && win.Iface != "any" {
		current, err := readInterfaceStats(win.Iface)
		if err == nil {
			previous := t.last[win.Iface]
			t.last[win.Iface] = current
			if previous.known {
				quality.RxBytes = deltaCounter(current.rxBytes, previous.rxBytes)
				quality.RxPackets = deltaCounter(current.rxPackets, previous.rxPackets)
				quality.RxDropped = deltaCounter(current.rxDropped, previous.rxDropped)
				quality.RxErrors = deltaCounter(current.rxErrors, previous.rxErrors)
				quality.TxBytes = deltaCounter(current.txBytes, previous.txBytes)
				quality.TxPackets = deltaCounter(current.txPackets, previous.txPackets)
				quality.TxDropped = deltaCounter(current.txDropped, previous.txDropped)
				quality.TxErrors = deltaCounter(current.txErrors, previous.txErrors)
			}
		}
	}
	win.Link.Drops += quality.RxDropped + quality.RxErrors
	win.Capture = &quality
}

func readInterfaceStats(iface string) (interfaceStats, error) {
	base := filepath.Join("/sys/class/net", iface, "statistics")
	stats := interfaceStats{known: true}
	var err error
	if stats.rxBytes, err = readUintFile(filepath.Join(base, "rx_bytes")); err != nil {
		return interfaceStats{}, err
	}
	if stats.rxPackets, err = readUintFile(filepath.Join(base, "rx_packets")); err != nil {
		return interfaceStats{}, err
	}
	if stats.rxDropped, err = readUintFile(filepath.Join(base, "rx_dropped")); err != nil {
		return interfaceStats{}, err
	}
	if stats.rxErrors, err = readUintFile(filepath.Join(base, "rx_errors")); err != nil {
		return interfaceStats{}, err
	}
	if stats.txBytes, err = readUintFile(filepath.Join(base, "tx_bytes")); err != nil {
		return interfaceStats{}, err
	}
	if stats.txPackets, err = readUintFile(filepath.Join(base, "tx_packets")); err != nil {
		return interfaceStats{}, err
	}
	if stats.txDropped, err = readUintFile(filepath.Join(base, "tx_dropped")); err != nil {
		return interfaceStats{}, err
	}
	if stats.txErrors, err = readUintFile(filepath.Join(base, "tx_errors")); err != nil {
		return interfaceStats{}, err
	}
	return stats, nil
}

func readUintFile(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
}

func deltaCounter(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}
