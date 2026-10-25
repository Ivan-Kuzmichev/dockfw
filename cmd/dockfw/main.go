//go:build linux

// Command dockfw applies nftables rules inside Docker containers' network
// namespaces based on container labels.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/config"
	"github.com/Ivan-Kuzmichev/dockfw/internal/daemon"
	"github.com/Ivan-Kuzmichev/dockfw/internal/docker"
	"github.com/Ivan-Kuzmichev/dockfw/internal/netns"
	"github.com/Ivan-Kuzmichev/dockfw/internal/resolver"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("dockfw", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: dockfw [--version] [healthz]\n\nConfiguration is read from FW_* environment variables, see README.\n")
	}
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Printf("dockfw %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	switch fs.Arg(0) {
	case "":
	case "healthz":
		if err := daemon.CheckHeartbeat(daemon.HeartbeatPath, daemon.HeartbeatMaxAge, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			return 1
		}
		return 0
	default:
		fs.Usage()
		return 2
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid configuration:", err)
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	log.Info("starting dockfw", "version", version, "commit", commit, "dry_run", cfg.DryRun, "unlabeled", cfg.Unlabeled, "network", cfg.Network)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	dc, err := docker.New()
	if err != nil {
		log.Error("cannot create docker client", "error", err)
		return 1
	}
	defer func() { _ = dc.Close() }()

	guard, err := netns.NewGuard()
	if err != nil {
		log.Error("cannot open host/own network namespace (is pid: host set?)", "error", err)
		return 1
	}
	defer func() { _ = guard.Close() }()

	lookup := &resolver.Lookuper{Guard: guard}
	d := daemon.New(cfg, log, dc, &daemon.NetnsEnforcer{Guard: guard}, lookup)
	if err := d.Run(ctx); err != nil {
		log.Error("daemon failed", "error", err)
		return 1
	}
	return 0
}
