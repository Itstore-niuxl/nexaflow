package main

import (
	"context"
	"log"

	"nexaflow/internal/config"
	"nexaflow/internal/storage/clickhouse"
)

func main() {
	cfg := config.Load()
	store := clickhouse.New(cfg.ClickHouseURL, cfg.Database)
	if err := store.Init(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Println("migration completed")
}

