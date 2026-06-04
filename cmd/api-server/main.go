package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nexaflow/internal/api"
	"nexaflow/internal/config"
	"nexaflow/internal/storage/clickhouse"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := clickhouse.New(cfg.ClickHouseURL, cfg.Database)
	if err := store.WaitInit(ctx, 30, 2*time.Second); err != nil {
		log.Printf("clickhouse init failed, API will serve degraded demo data: %v", err)
	}

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           api.New(store, cfg).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("api-server listening on %s", cfg.APIAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
