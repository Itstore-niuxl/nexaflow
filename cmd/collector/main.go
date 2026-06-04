package main

import (
	"context"
	"log"
	"os"
	"os/signal"
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
	go aggregate.New(cfg.Window, cfg.BandwidthMbps, func() config.Alerts {
		return config.LoadRuntime(cfg.RuntimePath, defaultRuntime).Alerts
	}).Run(packets, windows)

	log.Printf("collector started runtime_config=%s window=%s", cfg.RuntimePath, cfg.Window)
	for {
		select {
		case <-ctx.Done():
			log.Println("collector stopped")
			return
		case win := <-windows:
			if err := ch.WriteWindow(ctx, win); err != nil {
				log.Printf("clickhouse write failed: %v", err)
				if initErr := ch.Init(ctx); initErr != nil {
					log.Printf("clickhouse re-init failed: %v", initErr)
				}
			}
			if err := redis.WriteWindow(ctx, win); err != nil {
				log.Printf("redis write failed: %v", err)
			}
			log.Printf("window ts=%d bytes=%d packets=%d top_src=%d", win.Ts, win.Link.Bytes, win.Link.Packets, len(win.TopSrcIP))
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
