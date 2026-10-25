package config

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LabelPrefix != "fw." || cfg.Network != "fw" || cfg.Unlabeled != UnlabeledIgnore {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.DockerHost != "unix:///var/run/docker.sock" {
		t.Errorf("DockerHost = %q", cfg.DockerHost)
	}
	if cfg.ResolveInterval != 60*time.Second || cfg.ReconcileInterval != 30*time.Second || cfg.DomainTTLMin != 5*time.Minute {
		t.Errorf("unexpected intervals: %+v", cfg)
	}
	if cfg.LogLevel != slog.LevelInfo || cfg.DryRun {
		t.Errorf("unexpected log/dry-run: %+v", cfg)
	}
	if len(cfg.PrivateRanges) != 7 || cfg.PrivateRanges[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("PrivateRanges = %v", cfg.PrivateRanges)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"FW_LABEL_PREFIX":       "dockfw.",
		"FW_NETWORK":            "lan_fw",
		"FW_UNLABELED":          "deny",
		"FW_PRIVATE_RANGES":     " 10.1.2.3/8 , 192.168.0.0/16",
		"FW_RESOLVE_INTERVAL":   "10s",
		"FW_RECONCILE_INTERVAL": "0",
		"FW_DOMAIN_TTL_MIN":     "1m",
		"FW_LOG_LEVEL":          "debug",
		"FW_DRY_RUN":            "true",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LabelPrefix != "dockfw." || cfg.Network != "lan_fw" || cfg.Unlabeled != UnlabeledDeny {
		t.Errorf("unexpected: %+v", cfg)
	}
	if got := cfg.PrivateRanges[0]; got != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("prefix not masked: %v", got)
	}
	if cfg.ReconcileInterval != 0 || cfg.ResolveInterval != 10*time.Second || cfg.DomainTTLMin != time.Minute {
		t.Errorf("unexpected intervals: %+v", cfg)
	}
	if cfg.LogLevel != slog.LevelDebug || !cfg.DryRun {
		t.Errorf("unexpected log/dry-run: %+v", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	_, err := Load(env(map[string]string{
		"FW_LABEL_PREFIX":     "bad prefix",
		"FW_UNLABELED":        "block",
		"FW_PRIVATE_RANGES":   "10.0.0.0/33",
		"FW_RESOLVE_INTERVAL": "0",
		"FW_DOMAIN_TTL_MIN":   "-1m",
		"FW_LOG_LEVEL":        "loud",
		"FW_DRY_RUN":          "maybe",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, key := range []string{"FW_LABEL_PREFIX", "FW_UNLABELED", "FW_PRIVATE_RANGES", "FW_RESOLVE_INTERVAL", "FW_DOMAIN_TTL_MIN", "FW_LOG_LEVEL", "FW_DRY_RUN"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not mention %s: %v", key, err)
		}
	}
}
