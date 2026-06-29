package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fair-n-square-co/auth/cmd/auth/config"
	"github.com/fair-n-square-co/auth/internal/auth/db"
	"github.com/fair-n-square-co/auth/pkg/logger"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cfg, err := config.LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger.InitLogger(&cfg.Logger)

	// Establish the connection pool up front so a bad DSN fails fast, then
	// inject it into the server, which wires it through to module repositories.
	pool, err := db.NewPool(ctx, cfg.Db)
	if err != nil {
		slog.Error("failed to init db pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := server(ctx, cfg, pool); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}
