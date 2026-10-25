//go:build linux

package daemon

import (
	"context"
	"net/netip"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
	"github.com/Ivan-Kuzmichev/dockfw/internal/resolver"
)

type resolveTarget struct {
	id, name string
	pid      int
	ips      []netip.Addr
	domains  []string
}

// resolveLoop re-resolves fw.allow.domains every FW_RESOLVE_INTERVAL and
// immediately for containers that just started.
func (d *Daemon) resolveLoop(ctx context.Context) {
	t := time.NewTicker(d.cfg.ResolveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, target := range d.resolveTargets("") {
				d.resolve(ctx, target)
			}
		case id := <-d.resolveNow:
			for _, target := range d.resolveTargets(id) {
				d.resolve(ctx, target)
			}
		}
	}
}

// resolveTargets lists enforceable, unlocked containers with resolvable
// domains (only id, if given).
func (d *Daemon) resolveTargets(only string) []resolveTarget {
	d.mu.Lock()
	defer d.mu.Unlock()
	all := d.snapshot()
	var out []resolveTarget
	for id, e := range d.containers {
		if (only != "" && id != only) || !enforceable(e.info) {
			continue
		}
		res := policy.Build(&e.info.Container, all, d.policyOptions())
		if !res.Managed || res.Policy.Locked {
			continue
		}
		var names []string
		for _, dom := range res.Policy.Domains {
			if resolver.Resolvable(dom) {
				names = append(names, dom)
			}
		}
		if len(names) > 0 {
			out = append(out, resolveTarget{id: id, name: e.info.Name, pid: e.info.Pid, ips: e.info.IPs, domains: names})
		}
	}
	return out
}

// resolve looks the domains up from the container's own netns, keeps public
// answers and rebuilds the container's table with them.
func (d *Daemon) resolve(ctx context.Context, t resolveTarget) {
	log := d.log.With("container", t.name, "id", short(t.id))
	results, err := d.lookup.Lookup(ctx, t.pid, t.ips, t.domains)
	if err != nil {
		if d.confirmFunc(ctx, t.id, t.pid)() == nil {
			log.Warn("domain resolution failed", "error", err)
		}
		return
	}
	now := d.now()
	for _, r := range results {
		if r.Err != nil {
			log.Warn("cannot resolve domain", "domain", r.Name, "error", r.Err)
			continue
		}
		var public []resolver.Answer
		for _, a := range r.Answers {
			if resolver.Public(a.Addr, d.cfg.PrivateRanges) {
				public = append(public, a)
			} else {
				log.Warn("dropping non-public address from DNS answer (allow it via fw.allow.cidrs if intended)", "domain", r.Name, "addr", a.Addr.String())
			}
		}
		if len(r.Answers) == 0 {
			log.Warn("domain has no A records", "domain", r.Name)
		}
		d.cache.Add(t.id, public, now, d.cfg.DomainTTLMin)
	}
	d.q.add(t.id, jobRebuild)
}
