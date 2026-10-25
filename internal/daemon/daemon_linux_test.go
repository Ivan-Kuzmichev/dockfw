//go:build linux

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/config"
	"github.com/Ivan-Kuzmichev/dockfw/internal/docker"
	"github.com/Ivan-Kuzmichev/dockfw/internal/nft"
	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
)

type fakeDocker struct {
	mu         sync.Mutex
	containers map[string]*docker.Info
	events     chan docker.Event
	errs       chan error
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{containers: map[string]*docker.Info{}, events: make(chan docker.Event, 16), errs: make(chan error, 1)}
}

func (f *fakeDocker) Ping(context.Context) error { return nil }

func (f *fakeDocker) ListRunning(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.containers)), nil
}

func (f *fakeDocker) Inspect(_ context.Context, id string) (*docker.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.containers[id]
	if !ok {
		return nil, docker.ErrNotRunning
	}
	cp := *info
	return &cp, nil
}

func (f *fakeDocker) Events(context.Context) (<-chan docker.Event, <-chan error) {
	return f.events, f.errs
}

func (f *fakeDocker) start(info *docker.Info) {
	f.mu.Lock()
	f.containers[info.ID] = info
	f.mu.Unlock()
	f.events <- docker.Event{Kind: docker.EventStart, ContainerID: info.ID}
}

func (f *fakeDocker) stop(id string) {
	f.mu.Lock()
	delete(f.containers, id)
	f.mu.Unlock()
	f.events <- docker.Event{Kind: docker.EventDie, ContainerID: id}
}

type fakeTable struct {
	hash string
	text string
}

type fakeEnforcer struct {
	mu      sync.Mutex
	tables  map[int]fakeTable
	applies map[int]int
	fail    map[int]int // pid -> number of applies that must fail
	// gate, if set, is received from before every apply (to hold applies in
	// flight).
	gate chan struct{}
}

func newFakeEnforcer() *fakeEnforcer {
	return &fakeEnforcer{tables: map[int]fakeTable{}, applies: map[int]int{}, fail: map[int]int{}}
}

func (f *fakeEnforcer) SelfTest() error { return nil }

func (f *fakeEnforcer) Apply(pid int, rs *nft.Ruleset, confirm func() error) error {
	if err := confirm(); err != nil {
		return err
	}
	f.mu.Lock()
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies[pid]++
	if f.fail[pid] > 0 {
		f.fail[pid]--
		return errors.New("netlink: operation not supported")
	}
	f.tables[pid] = fakeTable{hash: rs.Hash, text: rs.Text()}
	return nil
}

func (f *fakeEnforcer) Verify(pid int, rs *nft.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tables[pid]
	if !ok {
		return nft.ErrMissing
	}
	if t.hash != rs.Hash {
		return nft.ErrDrift
	}
	return nil
}

func (f *fakeEnforcer) table(pid int) (fakeTable, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tables[pid]
	return t, ok
}

func (f *fakeEnforcer) count(pid int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies[pid]
}

func (f *fakeEnforcer) drop(pid int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tables, pid)
}

func info(name string, pid int, ip string, labels map[string]string) *docker.Info {
	i := &docker.Info{
		Container:   policy.Container{ID: "id-" + name, Name: name, Labels: labels, Networks: []string{"fw"}},
		Pid:         pid,
		NetworkMode: "fw",
	}
	if ip != "" {
		i.IPs = []netip.Addr{netip.MustParseAddr(ip)}
	}
	return i
}

type harness struct {
	t      *testing.T
	docker *fakeDocker
	enf    *fakeEnforcer
	d      *Daemon
	cancel context.CancelFunc
	done   chan struct{}
}

func start(t *testing.T, tweak func(*config.Config), initial ...*docker.Info) *harness {
	return startWith(t, tweak, nil, initial...)
}

// startWith lets the test prepare the fake enforcer before the daemon runs.
func startWith(t *testing.T, tweak func(*config.Config), prep func(*fakeEnforcer), initial ...*docker.Info) *harness {
	t.Helper()
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.ReconcileInterval = 0
	if tweak != nil {
		tweak(&cfg)
	}
	h := &harness{t: t, docker: newFakeDocker(), enf: newFakeEnforcer(), done: make(chan struct{})}
	if prep != nil {
		prep(h.enf)
	}
	for _, i := range initial {
		h.docker.containers[i.ID] = i
	}
	h.d = New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), h.docker, h.enf, nil)
	h.d.heartbeatPath = filepath.Join(t.TempDir(), "alive")
	h.d.retryDelays = []time.Duration{time.Millisecond, time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		if err := h.d.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-h.done
	})
	return h
}

func (h *harness) eventually(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *harness) tableHas(pid int, substrings ...string) func() bool {
	return func() bool {
		t, ok := h.enf.table(pid)
		if !ok {
			return false
		}
		for _, s := range substrings {
			if !strings.Contains(t.text, s) {
				return false
			}
		}
		return true
	}
}

func TestStartupAndDependents(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true", "fw.allow.containers": "b"})
	b := info("b", 102, "172.20.0.3", map[string]string{"fw.enable": "true"})
	unmanaged := info("plain", 103, "172.20.0.4", nil)
	h := start(t, nil, a, b, unmanaged)

	h.eventually("a applied with peer b", h.tableHas(101, "peers4 { type ipv4_addr; elements = { 172.20.0.3 }"))
	h.eventually("b applied with in-peer a", h.tableHas(102, "in_peers4 { type ipv4_addr; elements = { 172.20.0.2 }"))
	if h.enf.count(103) != 0 {
		t.Error("unlabeled container touched in ignore mode")
	}

	// b restarts with a new netns and a new IP: a must pick it up.
	h.docker.stop(b.ID)
	b2 := info("b", 202, "172.20.0.9", map[string]string{"fw.enable": "true"})
	h.docker.start(b2)
	h.eventually("a re-applied with b's new IP", h.tableHas(101, "elements = { 172.20.0.9 }"))
	h.eventually("new b applied", h.tableHas(202, "in_peers4 { type ipv4_addr; elements = { 172.20.0.2 }"))

	// A new container that references a: a gets it as in-peer.
	c := info("c", 104, "172.20.0.5", map[string]string{"fw.enable": "true", "fw.allow.containers": "a"})
	h.docker.start(c)
	h.eventually("a gets in-peer c", h.tableHas(101, "in_peers4 { type ipv4_addr; elements = { 172.20.0.5 }"))

	// c dies: a loses the in-peer.
	h.docker.stop(c.ID)
	h.eventually("a drops in-peer c", func() bool {
		t, _ := h.enf.table(101)
		return !strings.Contains(t.text, "172.20.0.5")
	})
}

// An event that arrives while the previous apply of a dependent container is
// still in flight must not be lost (regression: b restarted while a was being
// re-applied for b's death).
func TestEventDuringInFlightApply(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true", "fw.allow.containers": "b"})
	b := info("b", 102, "172.20.0.3", map[string]string{"fw.enable": "true"})
	h := start(t, nil, a, b)
	h.eventually("a applied with b", h.tableHas(101, "elements = { 172.20.0.3 }"))

	gate := make(chan struct{})
	h.enf.mu.Lock()
	h.enf.gate = gate
	h.enf.mu.Unlock()

	before := h.enf.count(101)
	h.docker.stop(b.ID) // a's re-apply (without b) is now held in flight
	h.eventually("a apply in flight", func() bool {
		h.d.q.mu.Lock()
		defer h.d.q.mu.Unlock()
		return h.d.q.active[a.ID]
	})
	h.docker.start(info("b", 202, "172.20.0.3", map[string]string{"fw.enable": "true"}))
	h.eventually("start event scheduled", func() bool {
		h.d.q.mu.Lock()
		defer h.d.q.mu.Unlock()
		return h.d.q.pending[b.ID] > 0 || h.d.q.active[b.ID]
	})
	h.enf.mu.Lock()
	h.enf.gate = nil
	h.enf.mu.Unlock()
	close(gate)

	h.eventually("in-flight apply done", func() bool { return h.enf.count(101) > before })
	h.eventually("a re-applied with b back", h.tableHas(101, "elements = { 172.20.0.3 }"))
}

func TestUnchangedPolicyIsNotReapplied(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	h := start(t, nil, a)
	h.eventually("a applied", h.tableHas(101))
	h.docker.start(info("x", 105, "172.20.0.7", nil))
	h.eventually("queue idle", func() bool { return h.d.q.idle() && len(h.docker.events) == 0 })
	time.Sleep(20 * time.Millisecond)
	if n := h.enf.count(101); n != 1 {
		t.Errorf("a applied %d times, want 1", n)
	}
}

func TestReconcileRestoresTable(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	h := start(t, func(c *config.Config) { c.ReconcileInterval = 20 * time.Millisecond }, a)
	h.eventually("a applied", h.tableHas(101))
	h.enf.drop(101)
	h.eventually("table restored", h.tableHas(101))
}

func TestApplyFailureDegradesThenRecovers(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	// 3 tries + the drop fallback fail; the reconcile fails once more, then succeeds.
	h := startWith(t, nil, func(f *fakeEnforcer) { f.fail[101] = 5 }, a)
	degraded := func() bool {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		e := h.d.containers[a.ID]
		return e != nil && e.degraded
	}
	h.eventually("degraded", degraded)
	h.eventually("queue idle", h.d.q.idle)
	h.d.scheduleAll(jobVerify) // what the reconcile ticker does
	h.eventually("recovered", h.tableHas(101))
	if degraded() {
		t.Error("still degraded after a successful apply")
	}
	if h.d.rejectAsDrop {
		t.Error("drop fallback must only engage when the drop variant succeeds")
	}
}

func TestRejectFallbackToDrop(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	// All reject attempts fail, the drop variant succeeds.
	h := startWith(t, nil, func(f *fakeEnforcer) { f.fail[101] = 3 }, a)
	h.eventually("drop fallback", h.tableHas(101, "counter drop"))
}

func TestSkippedNetworkModes(t *testing.T) {
	labels := map[string]string{"fw.enable": "true", "fw.allow.internet": "true"}
	host := info("host", 101, "", labels)
	host.NetworkMode = "host"
	none := info("none", 102, "", labels)
	none.NetworkMode = "none"
	shared := info("shared", 103, "", labels)
	shared.NetworkMode = "container:id-a"
	a := info("a", 104, "172.20.0.2", labels)
	h := start(t, nil, host, none, shared, a)
	h.eventually("a applied", h.tableHas(104))
	for _, pid := range []int{101, 102, 103} {
		if h.enf.count(pid) != 0 {
			t.Errorf("pid %d must never be touched", pid)
		}
	}
}

func TestUnlabeledDeny(t *testing.T) {
	plain := info("plain", 101, "172.20.0.2", nil)
	elsewhere := info("elsewhere", 102, "172.30.0.2", nil)
	elsewhere.Networks = []string{"bridge"}
	h := start(t, func(c *config.Config) { c.Unlabeled = config.UnlabeledDeny }, plain, elsewhere)
	h.eventually("plain locked", h.tableHas(101, "counter reject"))
	h.eventually("queue idle", h.d.q.idle)
	if h.enf.count(102) != 0 {
		t.Error("container outside FW_NETWORK touched")
	}
}

func TestInvalidLabelsLock(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true", "fw.allow.internet": "true", "fw.inbound": "any:http"})
	h := start(t, nil, a)
	h.eventually("a locked", h.tableHas(101, "ip daddr @domains4 accept\n    counter reject"))
	if tbl, _ := h.enf.table(101); strings.Contains(tbl.text, "private4") {
		t.Error("locked container must not get internet access")
	}
}

func TestDryRun(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	h := start(t, func(c *config.Config) { c.DryRun = true; c.ReconcileInterval = 10 * time.Millisecond }, a)
	h.eventually("marked applied", func() bool {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		e := h.d.containers[a.ID]
		return e != nil && e.applied != ""
	})
	time.Sleep(50 * time.Millisecond)
	if h.enf.count(101) != 0 {
		t.Error("dry run applied rules")
	}
}

func TestContainerGoneDuringApply(t *testing.T) {
	a := info("a", 101, "172.20.0.2", map[string]string{"fw.enable": "true"})
	h := start(t, nil, a)
	h.eventually("a applied", h.tableHas(101))

	// Inspect now reports another PID: confirm must fail, nothing is applied.
	h.docker.mu.Lock()
	moved := *a
	moved.Pid = 999
	h.docker.containers[a.ID] = &moved
	h.docker.mu.Unlock()
	h.d.sync(context.Background(), a.ID, jobRebuild)
	if h.enf.count(101) != 1 {
		t.Errorf("applied into a recycled PID: %d", h.enf.count(101))
	}
}

func TestQueueCoalescesAndSerializes(t *testing.T) {
	q := newQueue()
	q.add("a", jobVerify)
	q.add("a", jobApply)
	q.add("b", jobVerify)
	id, kind, _ := q.get()
	if id != "a" || kind != jobApply {
		t.Fatalf("got %s %d", id, kind)
	}
	q.add("a", jobVerify) // a is active: deferred
	id, _, _ = q.get()
	if id != "b" {
		t.Fatalf("a must not run twice concurrently, got %s", id)
	}
	q.done("b")
	q.done("a")
	id, kind, _ = q.get()
	if id != "a" || kind != jobVerify {
		t.Fatalf("deferred job lost: %s %d", id, kind)
	}
	q.done("a")
	if !q.idle() {
		t.Error("queue not idle")
	}
	q.close()
	if _, _, ok := q.get(); ok {
		t.Error("closed queue returned a job")
	}
}
