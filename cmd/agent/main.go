package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/evergreen-os/device-agent/internal/agent"
	"github.com/evergreen-os/device-agent/internal/config"
)

func main() {
	configPath := flag.String("config", "config/agent.yaml", "Path to agent configuration")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", slog.String("error", err.Error()))
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	agentInstance, err := agent.New(ctx, cfg)
	if err != nil {
		slog.Error("failed to initialise agent", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := agentInstance.Run(ctx); err != nil {
		if err == context.Canceled {
			fmt.Println("shutdown complete")
			return
		}
		slog.Error("agent exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
