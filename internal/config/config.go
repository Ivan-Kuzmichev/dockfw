// Package config reads and validates the daemon configuration from
// environment variables. There is no config file by design.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UnlabeledMode controls what happens to containers without the enable label.
type UnlabeledMode string

const (
	// UnlabeledIgnore leaves unlabeled containers untouched.
	UnlabeledIgnore UnlabeledMode = "ignore"
	// UnlabeledDeny locks down unlabeled containers attached to Config.Network.
	UnlabeledDeny UnlabeledMode = "deny"
)

// DefaultPrivateRanges is the default value of FW_PRIVATE_RANGES.
const DefaultPrivateRanges = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,fc00::/7,fe80::/10"

// Config is the validated daemon configuration.
type Config struct {
	DockerHost        string
	LabelPrefix       string
	Network           string
	Unlabeled         UnlabeledMode
	PrivateRanges     []netip.Prefix
	ResolveInterval   time.Duration
	ReconcileInterval time.Duration
	DomainTTLMin      time.Duration
	LogLevel          slog.Level
	DryRun            bool
}

var (
	prefixRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	networkRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// Load builds a Config from getenv (normally os.Getenv). All errors are
// collected so that a misconfigured daemon reports everything at once.
func Load(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	var errs []error
	cfg := Config{
		DockerHost:  get("DOCKER_HOST", "unix:///var/run/docker.sock"),
		LabelPrefix: get("FW_LABEL_PREFIX", "fw."),
		Network:     get("FW_NETWORK", "fw"),
		Unlabeled:   UnlabeledMode(get("FW_UNLABELED", string(UnlabeledIgnore))),
	}

	if !prefixRe.MatchString(cfg.LabelPrefix) {
		errs = append(errs, fmt.Errorf("FW_LABEL_PREFIX: invalid prefix %q", cfg.LabelPrefix))
	}
	if !networkRe.MatchString(cfg.Network) {
		errs = append(errs, fmt.Errorf("FW_NETWORK: invalid network name %q", cfg.Network))
	}
	if cfg.Unlabeled != UnlabeledIgnore && cfg.Unlabeled != UnlabeledDeny {
		errs = append(errs, fmt.Errorf("FW_UNLABELED: must be %q or %q, got %q", UnlabeledIgnore, UnlabeledDeny, cfg.Unlabeled))
	}

	ranges, err := ParsePrefixList(get("FW_PRIVATE_RANGES", DefaultPrivateRanges))
	if err != nil {
		errs = append(errs, fmt.Errorf("FW_PRIVATE_RANGES: %w", err))
	}
	cfg.PrivateRanges = ranges

	duration := func(key, def string, allowZero bool) time.Duration {
		raw := get(key, def)
		d, err := time.ParseDuration(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
		case d < 0 || (d == 0 && !allowZero):
			errs = append(errs, fmt.Errorf("%s: must be positive, got %q", key, raw))
		}
		return d
	}
	cfg.ResolveInterval = duration("FW_RESOLVE_INTERVAL", "60s", false)
	cfg.ReconcileInterval = duration("FW_RECONCILE_INTERVAL", "30s", true)
	cfg.DomainTTLMin = duration("FW_DOMAIN_TTL_MIN", "5m", false)

	if err := cfg.LogLevel.UnmarshalText([]byte(get("FW_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("FW_LOG_LEVEL: %w", err))
	}

	dry, err := strconv.ParseBool(get("FW_DRY_RUN", "false"))
	if err != nil {
		errs = append(errs, fmt.Errorf("FW_DRY_RUN: %w", err))
	}
	cfg.DryRun = dry

	return cfg, errors.Join(errs...)
}

// ParsePrefixList parses a comma-separated list of CIDR prefixes. Prefixes
// are masked to their network address.
func ParsePrefixList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("empty list")
	}
	return out, nil
}
