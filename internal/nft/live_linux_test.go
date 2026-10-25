//go:build linux

package nft

import (
	"errors"
	"net/netip"
	"os"
	"strconv"
	"testing"

	"github.com/Ivan-Kuzmichev/dockfw/internal/netns"
	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
)

// TestLive applies a ruleset in the network namespace of a real process. It
// needs root-like capabilities and a target PID, e.g.:
//
//	docker run -d --name t alpine sleep inf
//	DOCKFW_LIVE_PID=$(docker inspect -f '{{.State.Pid}}' t) go test -run Live ./internal/nft
//
// (run inside a container with --pid host and NET_ADMIN, SYS_ADMIN, SYS_PTRACE).
func TestLive(t *testing.T) {
	pid, _ := strconv.Atoi(os.Getenv("DOCKFW_LIVE_PID"))
	if pid == 0 {
		t.Skip("DOCKFW_LIVE_PID not set")
	}
	guard, err := netns.NewGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guard.Close() }()
	if err := guard.SelfTest(); err != nil {
		t.Fatalf("setns self-test: %v", err)
	}
	if _, err := guard.Open(1); !errors.Is(err, netns.ErrForbidden) {
		t.Fatalf("host netns must be refused, got %v", err)
	}

	h, err := guard.Open(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()

	p := policy.Policy{
		Container: "live", Mode: policy.ModeEnforce, Internet: true,
		Peers:   []netip.Addr{ip("172.20.0.11")},
		CIDRs:   []netip.Prefix{pfx("192.168.1.5/32"), pfx("10.8.0.0/24")},
		Inbound: []policy.Inbound{{Any: true, Port: 8080, Proto: policy.ProtoAny}},
		Private: private,
	}
	rs := Build(p, []DomainElem{{Addr: ip("93.184.215.14"), Timeout: 300e9}}, Options{})
	if err := Apply(h.Fd(), rs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Re-applying must be atomic and idempotent.
	if err := Apply(h.Fd(), rs); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if err := Verify(h.Fd(), rs); err != nil {
		t.Fatalf("verify: %v", err)
	}

	p.Internet = false
	other := Build(p, nil, Options{})
	if err := Verify(h.Fd(), other); !errors.Is(err, ErrDrift) {
		t.Fatalf("verify against a different policy: want drift, got %v", err)
	}
	if os.Getenv("DOCKFW_LIVE_KEEP") == "" {
		if err := Apply(h.Fd(), other); err != nil {
			t.Fatalf("apply other: %v", err)
		}
	}
	t.Log(rs.Text())
}
