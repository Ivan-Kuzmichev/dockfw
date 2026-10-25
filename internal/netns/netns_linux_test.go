//go:build linux

package netns

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// guardWithoutHost mimics AppArmor denying /proc/1/ns/net. It uses a fake
// /proc with the test process's own netns standing in for a container's.
func guardWithoutHost(t *testing.T, fib string) (*Guard, int) {
	t.Helper()
	self, err := open("/proc/self/ns/net")
	if err != nil {
		t.Skip("no /proc/self/ns/net:", err)
	}
	t.Cleanup(func() { _ = self.Close() })

	root := t.TempDir()
	const pid = 4242
	dir := filepath.Join(root, "4242")
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Any file works as a stand-in namespace for identity checks.
	if err := os.WriteFile(filepath.Join(dir, "ns", "net"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "net", "fib_trie"), []byte(fib), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Guard{self: self, procRoot: root}, pid
}

func TestGuardWithoutHost(t *testing.T) {
	g, pid := guardWithoutHost(t, fibTrie)
	if g.HostKnown() {
		t.Fatal("host must be unknown")
	}

	h, err := g.Open(pid, []netip.Addr{netip.MustParseAddr("172.19.0.2")})
	if err != nil {
		t.Fatalf("netns holding the container address refused: %v", err)
	}
	_ = h.Close()

	if _, err := g.Open(pid, []netip.Addr{netip.MustParseAddr("172.19.0.9")}); !errors.Is(err, ErrForbidden) {
		t.Errorf("netns without the container address: want ErrForbidden, got %v", err)
	}
	if _, err := g.Open(pid, nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("no IPs and unknown host: want ErrForbidden, got %v", err)
	}
	if _, err := g.Open(1, nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("PID 1: want ErrForbidden, got %v", err)
	}
	// Do must not dereference the unknown host (regression).
	if err := g.Do(g.self, func() error { return nil }); !errors.Is(err, ErrForbidden) {
		t.Errorf("Do in own netns: want ErrForbidden, got %v", err)
	}
	if err := g.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
