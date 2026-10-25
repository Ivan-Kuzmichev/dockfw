//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/config"
	"github.com/Ivan-Kuzmichev/dockfw/internal/docker"
	"github.com/Ivan-Kuzmichev/dockfw/internal/nft"
	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
	"github.com/Ivan-Kuzmichev/dockfw/internal/resolver"
)

// Docker is the subset of the Docker API the daemon needs.
type Docker interface {
	Ping(ctx context.Context) error
	ListRunning(ctx context.Context) ([]string, error)
	Inspect(ctx context.Context, id string) (*docker.Info, error)
	Events(ctx context.Context) (<-chan docker.Event, <-chan error)
}

// Enforcer programs and checks tables inside container namespaces.
type Enforcer interface {
	SelfTest() error
	// Apply opens the netns of pid, calls confirm (which must fail if pid no
	// longer belongs to the container) and atomically installs rs.
	Apply(pid int, rs *nft.Ruleset, confirm func() error) error
	// Verify checks that the netns of pid holds rs (nft.ErrMissing,
	// nft.ErrDrift otherwise).
	Verify(pid int, rs *nft.Ruleset) error
}

// Lookuper resolves names from inside the netns of pid.
type Lookuper interface {
	Lookup(ctx context.Context, pid int, names []string) ([]resolver.Result, error)
}

const workers = 4

// Daemon keeps the firewall of every running container in line with its
// labels.
type Daemon struct {
	cfg     config.Config
	log     *slog.Logger
	docker  Docker
	enf     Enforcer
	lookup  Lookuper
	cache   *resolver.Cache

	now           func() time.Time
	retryDelays   []time.Duration
	heartbeatPath string
	// resolveNow carries containers whose domains must be resolved right
	// away, without waiting for the ticker (spec §5 step 6).
	resolveNow chan string

	mu           sync.Mutex
	containers   map[string]*entry
	rejectAsDrop bool

	q *queue
}

type entry struct {
	info     *docker.Info
	applied  string // hash of the policy in the kernel; "" = nothing yet
	degraded bool
	// requested is the policy hash last scheduled by scheduleChanged. An
	// apply may be in flight, so comparing with applied alone could miss a
	// change that arrives meanwhile.
	requested string
}

// New creates a daemon. lookup may be nil (no domain resolution).
func New(cfg config.Config, log *slog.Logger, d Docker, enf Enforcer, lookup Lookuper) *Daemon {
	return &Daemon{
		cfg:           cfg,
		log:           log,
		docker:        d,
		enf:           enf,
		lookup:        lookup,
		cache:         resolver.NewCache(),
		resolveNow:    make(chan string, 64),
		now:           time.Now,
		retryDelays:   []time.Duration{100 * time.Millisecond, 500 * time.Millisecond},
		heartbeatPath: HeartbeatPath,
		containers:    map[string]*entry{},
		q:             newQueue(),
	}
}

// Run blocks until ctx is cancelled. It returns an error only if the daemon
// cannot start at all.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.docker.Ping(ctx); err != nil {
		return fmt.Errorf("docker API: %w", err)
	}
	if err := d.enf.SelfTest(); err != nil {
		return fmt.Errorf("cannot enter network namespaces (need pid: host, SYS_ADMIN, NET_ADMIN, SYS_PTRACE): %w", err)
	}
	d.checkLogSysctl()

	wg := d.q.run(ctx, workers, func(id string, kind jobKind) { d.sync(ctx, id, kind) })
	defer wg.Wait()

	if d.cfg.ReconcileInterval > 0 {
		go d.every(ctx, d.cfg.ReconcileInterval, func() { d.scheduleAll(jobVerify) })
	}
	if d.lookup != nil {
		go d.resolveLoop(ctx)
	}

	d.heartbeat()
	hb := time.NewTicker(HeartbeatInterval)
	defer hb.Stop()

	backoff := time.Second
	for {
		err := d.watch(ctx, hb.C)
		if ctx.Err() != nil {
			d.log.Info("shutting down")
			return nil
		}
		d.log.Warn("docker event stream lost, resyncing", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// watch subscribes to events, does a full resync (so nothing that happened
// before the subscription is missed) and processes events until the stream
// fails.
func (d *Daemon) watch(ctx context.Context, hb <-chan time.Time) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	evs, errc := d.docker.Events(ctx)
	start := d.now()
	if err := d.resync(ctx); err != nil {
		return err
	}
	d.log.Info("full resync done", "containers", d.count(), "duration", d.now().Sub(start).String())

	for {
		select {
		case ev, ok := <-evs:
			if !ok {
				evs = nil
				continue
			}
			d.handle(ctx, ev)
		case err := <-errc:
			return err
		case <-hb:
			d.heartbeat()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (d *Daemon) every(ctx context.Context, interval time.Duration, fn func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

func (d *Daemon) heartbeat() {
	if err := WriteHeartbeat(d.heartbeatPath, d.now()); err != nil {
		d.log.Error("cannot write heartbeat", "path", d.heartbeatPath, "error", err)
	}
}

// checkLogSysctl warns when audit logs from container namespaces would be
// dropped by the kernel.
func (d *Daemon) checkLogSysctl() {
	const path = "/proc/sys/net/netfilter/nf_log_all_netns"
	b, err := os.ReadFile(path)
	if err != nil {
		// The sysctl only exists in the host netns; with network_mode: none we
		// cannot see it and must not enter the host netns to check.
		d.log.Info("cannot check net.netfilter.nf_log_all_netns from the daemon's netns; fw.mode=audit logs reach the host kernel log only if it is 1", "error", err)
		return
	}
	if strings.TrimSpace(string(b)) != "1" {
		d.log.Warn("net.netfilter.nf_log_all_netns is 0: fw.mode=audit log lines will not appear in the host kernel log; run sysctl -w net.netfilter.nf_log_all_netns=1")
	}
}

func (d *Daemon) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.containers)
}

// resync replaces the known state with a full listing.
func (d *Daemon) resync(ctx context.Context) error {
	ids, err := d.docker.ListRunning(ctx)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	infos := make(map[string]*docker.Info, len(ids))
	for _, id := range ids {
		info, err := d.docker.Inspect(ctx, id)
		if errors.Is(err, docker.ErrNotRunning) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", short(id), err)
		}
		infos[id] = info
	}

	d.mu.Lock()
	for id := range d.containers {
		if _, ok := infos[id]; !ok {
			delete(d.containers, id)
		}
	}
	for id, info := range infos {
		d.store(id, info)
	}
	d.mu.Unlock()

	for _, info := range infos {
		d.noteSkipped(info)
	}
	d.scheduleAll(jobVerify)
	return nil
}

// store records info; a new PID means a new netns, so nothing is applied yet.
// d.mu must be held.
func (d *Daemon) store(id string, info *docker.Info) {
	if e, ok := d.containers[id]; ok && e.info.Pid == info.Pid {
		e.info = info
		return
	}
	d.containers[id] = &entry{info: info}
}

func (d *Daemon) handle(ctx context.Context, ev docker.Event) {
	switch ev.Kind {
	case docker.EventStart, docker.EventNetwork:
		info, err := d.docker.Inspect(ctx, ev.ContainerID)
		switch {
		case errors.Is(err, docker.ErrNotRunning):
			d.forget(ev.ContainerID)
		case err != nil:
			d.log.Error("inspect failed", "id", short(ev.ContainerID), "error", err)
			return
		default:
			d.mu.Lock()
			d.store(ev.ContainerID, info)
			d.mu.Unlock()
			if ev.Kind == docker.EventStart {
				d.noteSkipped(info)
			}
		}
	case docker.EventDie:
		d.forget(ev.ContainerID)
	}
	// Peers of other containers may have changed (spec §5 steps 3-5).
	d.scheduleChanged()
	if ev.Kind == docker.EventStart {
		select {
		case d.resolveNow <- ev.ContainerID:
		default: // the ticker will catch up
		}
	}
}

func (d *Daemon) forget(id string) {
	d.mu.Lock()
	delete(d.containers, id)
	d.mu.Unlock()
	d.cache.Forget(id)
}

// noteSkipped logs containers whose netns dockfw must never touch.
func (d *Daemon) noteSkipped(info *docker.Info) {
	switch {
	case info.HostNetwork():
		if res := policy.Build(&info.Container, nil, d.policyOptions()); res.Managed {
			d.log.Warn("network_mode: host, skipped (its netns is the host's)", "container", info.Name)
		}
	case info.SharedNetwork():
		if res := policy.Build(&info.Container, nil, d.policyOptions()); res.Managed {
			d.log.Warn("network_mode: container:..., skipped (rules of the namespace owner apply)", "container", info.Name, "network_mode", info.NetworkMode)
		}
	}
}

func (d *Daemon) policyOptions() policy.Options {
	return policy.Options{
		Prefix:        d.cfg.LabelPrefix,
		DenyUnlabeled: d.cfg.Unlabeled == config.UnlabeledDeny,
		Network:       d.cfg.Network,
		PrivateRanges: d.cfg.PrivateRanges,
	}
}

// snapshot returns all known containers. d.mu must be held. Infos are never
// mutated after being stored, so sharing the pointers is safe.
func (d *Daemon) snapshot() []*policy.Container {
	all := make([]*policy.Container, 0, len(d.containers))
	for _, e := range d.containers {
		all = append(all, &e.info.Container)
	}
	return all
}

// scheduleChanged queues an apply for every managed container whose desired
// policy differs from what is in its kernel table or from what was last
// requested (an apply for the previous state may still be in flight).
func (d *Daemon) scheduleChanged() {
	d.mu.Lock()
	all := d.snapshot()
	var ids []string
	for id, e := range d.containers {
		if !enforceable(e.info) {
			continue
		}
		res := policy.Build(&e.info.Container, all, d.policyOptions())
		if !res.Managed {
			continue
		}
		want := res.Policy.Hash()
		if want != e.applied || want != e.requested || e.degraded {
			ids = append(ids, id)
		}
		e.requested = want
	}
	d.mu.Unlock()
	for _, id := range ids {
		d.q.add(id, jobApply)
	}
}

// scheduleAll queues every container (reconcile).
func (d *Daemon) scheduleAll(kind jobKind) {
	d.mu.Lock()
	ids := make([]string, 0, len(d.containers))
	for id, e := range d.containers {
		if enforceable(e.info) {
			ids = append(ids, id)
		}
	}
	d.mu.Unlock()
	for _, id := range ids {
		d.q.add(id, kind)
	}
}

func enforceable(info *docker.Info) bool {
	return !info.HostNetwork() && !info.NoNetwork() && !info.SharedNetwork() && info.Pid > 1
}

// sync brings one container's table in line with its policy.
func (d *Daemon) sync(ctx context.Context, id string, kind jobKind) {
	d.mu.Lock()
	e := d.containers[id]
	if e == nil {
		d.mu.Unlock()
		return
	}
	info, applied, degraded, rejectAsDrop := e.info, e.applied, e.degraded, d.rejectAsDrop
	all := d.snapshot()
	d.mu.Unlock()

	if !enforceable(info) {
		return
	}
	res := policy.Build(&info.Container, all, d.policyOptions())
	if !res.Managed {
		for _, w := range res.Warnings {
			d.log.Warn(w, "container", info.Name)
		}
		return
	}
	pol := res.Policy
	hash := pol.Hash()
	log := d.log.With("container", info.Name, "id", short(id))

	if applied == hash && !degraded {
		switch kind {
		case jobApply:
			return
		case jobVerify:
			if d.cfg.DryRun {
				return
			}
			err := d.enf.Verify(info.Pid, nft.Build(pol, nil, nft.Options{RejectAsDrop: rejectAsDrop}))
			if err == nil {
				return
			}
			if !errors.Is(err, nft.ErrMissing) && !errors.Is(err, nft.ErrDrift) {
				if cerr := d.confirmFunc(ctx, id, info.Pid)(); cerr != nil {
					return // restarted or stopped; its own event handles it
				}
			}
			log.Warn("reconcile: table missing or modified, re-applying", "error", err)
		}
	} else if kind == jobVerify && applied != "" && applied != hash {
		log.Warn("reconcile: policy changed without a matching event, re-applying", "applied", applied, "want", hash)
	}

	for _, err := range res.Errors {
		log.Error("invalid fw labels, container locked down", "error", err)
	}
	for _, w := range res.Warnings {
		log.Warn(w)
	}
	if len(res.Missing) > 0 {
		log.Info("referenced containers are not running yet", "refs", res.Missing)
	}
	if applied == "" && info.HasNetAdmin() {
		log.Warn("protected container has NET_ADMIN or is privileged and can remove its own rules")
	}

	var elems []nft.DomainElem
	for _, e := range d.cache.Elements(id, d.now()) {
		elems = append(elems, nft.DomainElem{Addr: e.Addr, Timeout: e.Timeout})
	}
	rs := nft.Build(pol, elems, nft.Options{RejectAsDrop: rejectAsDrop})
	log.Debug("generated ruleset", "hash", hash, "policy", pol.Text(), "ruleset", rs.Text())

	attrs := []any{
		"hash", hash, "locked", pol.Locked, "mode", pol.Mode, "internet", pol.Internet,
		"peers", len(pol.Peers), "in_peers", len(pol.InPeers), "domains", len(pol.Domains),
		"domain_ips", len(elems), "cidrs", len(pol.CIDRs), "inbound", len(pol.Inbound),
	}
	if d.cfg.DryRun {
		log.Info("dry run: policy not applied", append(attrs, "ruleset", rs.Text())...)
		d.markApplied(id, info, hash)
		return
	}

	start := d.now()
	confirm := d.confirmFunc(ctx, id, info.Pid)
	err := d.applyWithRetry(ctx, info.Pid, rs, confirm)
	if err != nil && !rejectAsDrop && !errors.Is(err, errContainerGone) {
		dropRS := nft.Build(pol, elems, nft.Options{RejectAsDrop: true})
		if derr := d.enf.Apply(info.Pid, dropRS, confirm); derr == nil {
			d.mu.Lock()
			d.rejectAsDrop = true
			d.mu.Unlock()
			log.Warn("kernel rejected 'reject with icmpx'; falling back to drop for all containers", "error", err)
			err = nil
		}
	}
	switch {
	case errors.Is(err, errContainerGone):
		log.Debug("container restarted or stopped during apply", "error", err)
	case err != nil:
		log.Error("failed to apply policy, container marked degraded; reconcile will retry", "error", err)
		d.markDegraded(id, info)
	default:
		d.markApplied(id, info, hash)
		level := slog.LevelInfo
		if kind == jobRebuild && applied == hash {
			level = slog.LevelDebug // periodic domain refresh, nothing new
		}
		log.Log(ctx, level, "policy applied", append(attrs, "duration", d.now().Sub(start).String())...)
	}
}

var errContainerGone = errors.New("container is no longer the same running process")

func (d *Daemon) confirmFunc(ctx context.Context, id string, pid int) func() error {
	return func() error {
		info, err := d.docker.Inspect(ctx, id)
		if errors.Is(err, docker.ErrNotRunning) {
			return errContainerGone
		}
		if err != nil {
			return err
		}
		if info.Pid != pid {
			return errContainerGone
		}
		return nil
	}
}

func (d *Daemon) applyWithRetry(ctx context.Context, pid int, rs *nft.Ruleset, confirm func() error) error {
	var err error
	for attempt := 0; ; attempt++ {
		err = d.enf.Apply(pid, rs, confirm)
		if err == nil || errors.Is(err, errContainerGone) || attempt >= len(d.retryDelays) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(d.retryDelays[attempt]):
		}
	}
}

func (d *Daemon) markApplied(id string, info *docker.Info, hash string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.containers[id]; e != nil && e.info.Pid == info.Pid {
		e.applied, e.degraded = hash, false
	}
}

func (d *Daemon) markDegraded(id string, info *docker.Info) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.containers[id]; e != nil && e.info.Pid == info.Pid {
		e.degraded = true
	}
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
