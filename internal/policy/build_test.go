package policy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Ivan-Kuzmichev/dockfw/internal/config"
)

func ctr(name, project, service string, ips []string, labels map[string]string) *Container {
	l := map[string]string{}
	for k, v := range labels {
		l[k] = v
	}
	if project != "" {
		l[LabelComposeProject] = project
	}
	if service != "" {
		l[LabelComposeService] = service
	}
	c := &Container{ID: "id-" + name, Name: name, Labels: l, Networks: []string{"fw"}}
	for _, ip := range ips {
		c.IPs = append(c.IPs, netip.MustParseAddr(ip))
	}
	return c
}

func opts() Options {
	ranges, err := config.ParsePrefixList(config.DefaultPrivateRanges)
	if err != nil {
		panic(err)
	}
	return Options{Prefix: "fw.", Network: "fw", PrivateRanges: ranges}
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func on(l map[string]string) map[string]string {
	l["fw.enable"] = "true"
	return l
}

func TestBuildPeersAndSymmetry(t *testing.T) {
	a := ctr("a", "p", "a", []string{"172.20.0.2"}, on(map[string]string{"fw.allow.containers": "b"}))
	b := ctr("b", "p", "b", []string{"172.20.0.3", "172.21.0.3"}, on(map[string]string{}))
	c := ctr("c", "p", "c", []string{"172.20.0.4"}, on(map[string]string{}))
	all := []*Container{a, b, c}

	ra := Build(a, all, opts())
	if !ra.Managed || ra.Policy.Locked || len(ra.Errors) > 0 {
		t.Fatalf("a: %+v", ra)
	}
	if !slices.Equal(ra.Policy.Peers, addrs("172.20.0.3", "172.21.0.3")) {
		t.Errorf("a peers = %v", ra.Policy.Peers)
	}
	if len(ra.Policy.InPeers) != 0 {
		t.Errorf("a in-peers = %v (symmetry must be one-way)", ra.Policy.InPeers)
	}

	rb := Build(b, all, opts())
	if !slices.Equal(rb.Policy.InPeers, addrs("172.20.0.2")) || len(rb.Policy.Peers) != 0 {
		t.Errorf("b peers=%v in-peers=%v", rb.Policy.Peers, rb.Policy.InPeers)
	}

	rc := Build(c, all, opts())
	if len(rc.Policy.InPeers) != 0 || len(rc.Policy.Peers) != 0 {
		t.Errorf("c must be isolated: %+v", rc.Policy)
	}
}

func TestBuildMissingPeer(t *testing.T) {
	a := ctr("a", "", "", []string{"172.20.0.2"}, on(map[string]string{"fw.allow.containers": "b,nohost"}))
	nohost := ctr("nohost", "", "", nil, nil) // network_mode none/host: no IPs
	r := Build(a, []*Container{a, nohost}, opts())
	if r.Policy.Locked || len(r.Policy.Peers) != 0 {
		t.Fatalf("unexpected: %+v", r.Policy)
	}
	if !slices.Equal(r.Missing, []string{"b", "nohost"}) {
		t.Errorf("missing = %v", r.Missing)
	}
}

func TestMatchOrder(t *testing.T) {
	byName := ctr("jackett", "other", "indexer", []string{"10.0.0.1"}, nil)
	svc1 := ctr("torrents-jackett-1", "torrents", "jackett", []string{"10.0.0.2"}, nil)
	svc2 := ctr("torrents-jackett-2", "torrents", "jackett", []string{"10.0.0.3"}, nil)
	media := ctr("media-jackett-1", "media", "jackett", []string{"10.0.0.4"}, nil)

	// 1. Exact container name wins over service names.
	got, err := Match(Ref{Name: "jackett"}, []*Container{svc1, media, byName})
	if err != nil || len(got) != 1 || got[0] != byName {
		t.Errorf("name match: %v %v", got, err)
	}
	// 2. project/service, replicas all match.
	got, err = Match(Ref{Project: "torrents", Name: "jackett"}, []*Container{svc1, svc2, media})
	if err != nil || len(got) != 2 {
		t.Errorf("project/service: %v %v", got, err)
	}
	// 3. Bare service in a single project.
	got, err = Match(Ref{Name: "jackett"}, []*Container{svc1, svc2})
	if err != nil || len(got) != 2 {
		t.Errorf("bare service: %v %v", got, err)
	}
	// 3. Bare service in two projects is ambiguous.
	_, err = Match(Ref{Name: "jackett"}, []*Container{svc1, media})
	if err == nil || !strings.Contains(err.Error(), "media/jackett, torrents/jackett") {
		t.Errorf("ambiguous: %v", err)
	}
	// project/service never matches by container name.
	got, _ = Match(Ref{Project: "other", Name: "jackett"}, []*Container{byName})
	if len(got) != 0 {
		t.Errorf("project/service matched a container name: %v", got)
	}
}

func TestBuildAmbiguousLocks(t *testing.T) {
	a := ctr("a", "p", "a", []string{"172.20.0.2"}, on(map[string]string{
		"fw.allow.containers": "jackett",
		"fw.allow.internet":   "true",
		"fw.inbound":          "any:80",
	}))
	j1 := ctr("x-jackett-1", "x", "jackett", []string{"172.20.0.3"}, on(map[string]string{}))
	j2 := ctr("y-jackett-1", "y", "jackett", []string{"172.20.0.4"}, on(map[string]string{}))
	all := []*Container{a, j1, j2}

	r := Build(a, all, opts())
	assertLocked(t, r, "fw.allow.containers", "ambiguous")

	// A locked initiator contributes no symmetric access.
	if rj := Build(j1, all, opts()); len(rj.Policy.InPeers) != 0 {
		t.Errorf("j1 in-peers = %v", rj.Policy.InPeers)
	}
}

func TestBuildInvalidLabelLocks(t *testing.T) {
	a := ctr("a", "", "", []string{"172.20.0.2"}, on(map[string]string{
		"fw.allow.containers": "b",
		"fw.allow.internet":   "true",
		"fw.allow.cidrs":      "192.168.1.0/24",
		"fw.inbound":          "any:80,any:notaport",
		"fw.mode":             "audit",
	}))
	b := ctr("b", "", "", []string{"172.20.0.3"}, on(map[string]string{}))
	r := Build(a, []*Container{a, b}, opts())
	assertLocked(t, r, "fw.inbound", "invalid port")

	if rb := Build(b, []*Container{a, b}, opts()); len(rb.Policy.InPeers) != 0 {
		t.Errorf("invalid initiator must not open b: %v", rb.Policy.InPeers)
	}
}

func TestBuildLockedKeepsSymmetry(t *testing.T) {
	a := ctr("a", "", "", []string{"172.20.0.2"}, on(map[string]string{"fw.allow.containers": "b"}))
	b := ctr("b", "", "", []string{"172.20.0.3"}, on(map[string]string{"fw.mode": "bogus"}))
	r := Build(b, []*Container{a, b}, opts())
	if !r.Policy.Locked || !slices.Equal(r.Policy.InPeers, addrs("172.20.0.2")) {
		t.Errorf("locked b must still accept declared peers: %+v", r.Policy)
	}
}

func assertLocked(t *testing.T, r Result, wantLabel, wantErr string) {
	t.Helper()
	p := r.Policy
	if !r.Managed || !p.Locked || p.Mode != ModeEnforce || p.Internet ||
		len(p.Peers)+len(p.CIDRs)+len(p.Domains)+len(p.Inbound) != 0 {
		t.Errorf("not fully locked: %+v", p)
	}
	if len(r.Errors) == 0 {
		t.Fatal("no error reported")
	}
	msg := r.Errors[0].Error()
	if !strings.Contains(msg, wantLabel) || !strings.Contains(msg, wantErr) {
		t.Errorf("error %q must mention %q and %q", msg, wantLabel, wantErr)
	}
}

func TestBuildUnlabeled(t *testing.T) {
	plain := ctr("plain", "", "", []string{"172.20.0.5"}, nil)
	other := ctr("other", "", "", []string{"172.30.0.5"}, nil)
	other.Networks = []string{"bridge"}
	typo := ctr("typo", "", "", []string{"172.20.0.6"}, map[string]string{"fw.allow.internet": "true"})

	ignore := opts()
	if r := Build(plain, nil, ignore); r.Managed {
		t.Error("ignore mode must not manage unlabeled containers")
	}
	if r := Build(typo, nil, ignore); r.Managed || len(r.Warnings) != 1 {
		t.Errorf("fw.* without fw.enable must warn: %+v", r)
	}

	deny := opts()
	deny.DenyUnlabeled = true
	r := Build(plain, nil, deny)
	if !r.Managed || !r.Policy.Locked || r.Policy.LockReason != "unlabeled" {
		t.Errorf("deny mode must lock: %+v", r)
	}
	if r := Build(other, nil, deny); r.Managed {
		t.Error("deny mode only applies to FW_NETWORK")
	}
	disabled := ctr("disabled", "", "", []string{"172.20.0.7"}, map[string]string{"fw.enable": "false"})
	if r := Build(disabled, nil, deny); !r.Policy.Locked {
		t.Error("fw.enable=false counts as unlabeled")
	}
}

func TestBuildWildcardWarns(t *testing.T) {
	a := ctr("a", "", "", nil, on(map[string]string{"fw.allow.domains": "*.tmdb.org,api.themoviedb.org"}))
	r := Build(a, nil, opts())
	if r.Policy.Locked || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "*.tmdb.org") {
		t.Errorf("unexpected: %+v", r)
	}
}

func TestPrivateIsIPv4Only(t *testing.T) {
	r := Build(ctr("a", "", "", nil, on(map[string]string{})), nil, opts())
	for _, p := range r.Policy.Private {
		if !p.Addr().Is4() {
			t.Errorf("non-IPv4 private range %v", p)
		}
	}
	if len(r.Policy.Private) != 5 {
		t.Errorf("private = %v", r.Policy.Private)
	}
}

func TestHash(t *testing.T) {
	base := Policy{Container: "a", Mode: ModeEnforce, Peers: addrs("172.20.0.3")}
	h := base.Hash()
	if h != base.Hash() || len(h) != 16 {
		t.Fatalf("hash not stable: %q", h)
	}
	variants := []func(p *Policy){
		func(p *Policy) { p.Container = "b" },
		func(p *Policy) { p.Locked, p.LockReason = true, "unlabeled" },
		func(p *Policy) { p.Mode = ModeAudit },
		func(p *Policy) { p.Internet = true },
		func(p *Policy) { p.Peers = addrs("172.20.0.4") },
		func(p *Policy) { p.InPeers = addrs("172.20.0.4") },
		func(p *Policy) { p.CIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
		func(p *Policy) { p.Domains = []string{"example.com"} },
		func(p *Policy) { p.Inbound = []Inbound{{Any: true, Port: 80, Proto: ProtoTCP}} },
		func(p *Policy) { p.Inbound = []Inbound{{Any: true, Port: 80, Proto: ProtoUDP}} },
		func(p *Policy) { p.Private = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} },
	}
	seen := map[string]int{h: -1}
	for i, mutate := range variants {
		p := base
		mutate(&p)
		got := p.Hash()
		if j, dup := seen[got]; dup {
			t.Errorf("variant %d hash collides with %d", i, j)
		}
		seen[got] = i
	}
}

func TestBuildIsOrderIndependent(t *testing.T) {
	a := ctr("a", "", "", []string{"172.20.0.2"}, on(map[string]string{"fw.allow.containers": "c,b"}))
	b := ctr("b", "", "", []string{"172.20.0.9"}, on(map[string]string{}))
	c := ctr("c", "", "", []string{"172.20.0.3"}, on(map[string]string{}))
	h1 := Build(a, []*Container{a, b, c}, opts()).Policy.Hash()
	h2 := Build(a, []*Container{c, b, a}, opts()).Policy.Hash()
	if h1 != h2 {
		t.Error("policy depends on container order")
	}
}
