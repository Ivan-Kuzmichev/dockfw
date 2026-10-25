//go:build linux

package nft

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

func goldenCompare(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s mismatch (run go test -update to accept)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

var private = []netip.Prefix{pfx("10.0.0.0/8"), pfx("172.16.0.0/12"), pfx("192.168.0.0/16"), pfx("100.64.0.0/10"), pfx("169.254.0.0/16")}

func TestGolden(t *testing.T) {
	tests := []struct {
		name    string
		policy  policy.Policy
		domains []DomainElem
		opt     Options
	}{
		{
			name:   "locked",
			policy: policy.Policy{Container: "vaultwarden", Locked: true, LockReason: "invalid labels", Mode: policy.ModeEnforce, Private: private},
		},
		{
			name: "domains-and-peers",
			policy: policy.Policy{
				Container: "dublyarr", Mode: policy.ModeEnforce,
				Peers:   []netip.Addr{ip("172.20.0.11"), ip("172.20.0.12")},
				Domains: []string{"api.themoviedb.org"},
				Inbound: []policy.Inbound{{Source: pfx("192.168.1.0/24"), Port: 3000, Proto: policy.ProtoAny}},
				Private: private,
			},
			domains: []DomainElem{
				{Addr: ip("13.224.1.2"), Timeout: 10 * time.Minute},
				{Addr: ip("13.224.1.1"), Timeout: 5*time.Minute + 300*time.Millisecond},
				{Addr: ip("2600::1"), Timeout: time.Minute}, // IPv6 is skipped in v1
				{Addr: ip("13.224.1.3"), Timeout: 0},       // expired
			},
		},
		{
			name: "internet",
			policy: policy.Policy{
				Container: "qbittorrent", Mode: policy.ModeEnforce, Internet: true,
				InPeers: []netip.Addr{ip("172.20.0.10")},
				CIDRs:   []netip.Prefix{pfx("192.168.1.5/32"), pfx("10.8.0.0/24"), pfx("10.8.1.0/24"), pfx("10.8.0.0/16")},
				Inbound: []policy.Inbound{
					{Source: pfx("192.168.1.10/32"), Port: 8787, Proto: policy.ProtoTCP},
					{Source: pfx("0.0.0.0/0"), Port: 8080, Proto: policy.ProtoTCP},
					{Any: true, Port: 54890, Proto: policy.ProtoAny},
				},
				Private: private,
			},
		},
		{
			name:   "audit",
			policy: policy.Policy{Container: "jackett", Mode: policy.ModeAudit, Internet: true, Private: private},
		},
		{
			name:   "reject-as-drop",
			policy: policy.Policy{Container: "c", Mode: policy.ModeEnforce, Private: private},
			opt:    Options{RejectAsDrop: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := Build(tt.policy, tt.domains, tt.opt)
			if rs.Hash != tt.policy.Hash() {
				t.Errorf("hash %s != policy hash %s", rs.Hash, tt.policy.Hash())
			}
			goldenCompare(t, tt.name, rs.Dump())
		})
	}
}

func TestIntervalMerge(t *testing.T) {
	c := intervalElems([]netip.Prefix{pfx("0.0.0.0/0")})
	if len(c.elems) != 1 || c.elems[0].IntervalEnd {
		t.Errorf("0.0.0.0/0 must be a single open-ended element: %+v", c.elems)
	}
	c = intervalElems([]netip.Prefix{pfx("10.0.0.0/24"), pfx("10.0.1.0/24"), pfx("10.0.0.128/25"), pfx("255.255.255.255/32")})
	if got := strings.Join(c.text, " "); got != "10.0.0.0-10.0.1.255 255.255.255.255-255.255.255.255" {
		t.Errorf("merged = %q", got)
	}
	if len(c.elems) != 3 {
		t.Errorf("want start/end + open-ended start, got %d elements", len(c.elems))
	}
}

func TestLogPrefix(t *testing.T) {
	if got := logPrefix("a b\"c"); got != "dockfw a_b_c " {
		t.Errorf("logPrefix = %q", got)
	}
	if got := logPrefix(strings.Repeat("x", 300)); len(got) > 127 {
		t.Errorf("prefix too long: %d", len(got))
	}
}
