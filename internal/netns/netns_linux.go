//go:build linux

package netns

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// ErrForbidden is returned when a namespace must never be entered: the host
// namespace (PID 1's, which is the host's with pid: host) or the daemon's own.
var ErrForbidden = errors.New("refusing to touch host or daemon network namespace")

// Handle is an open reference to a network namespace. Holding it keeps the
// namespace alive even if the owning process exits.
type Handle struct {
	f   *os.File
	dev uint64
	ino uint64
}

// Fd returns the namespace file descriptor.
func (h *Handle) Fd() int { return int(h.f.Fd()) }

// Close releases the handle.
func (h *Handle) Close() error { return h.f.Close() }

// ID identifies the namespace (device and inode of the nsfs file).
func (h *Handle) ID() string { return fmt.Sprintf("%d:%d", h.dev, h.ino) }

// Same reports whether both handles refer to the same namespace.
func (h *Handle) Same(o *Handle) bool { return h.dev == o.dev && h.ino == o.ino }

func open(path string) (*Handle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	return &Handle{f: f, dev: st.Dev, ino: st.Ino}, nil
}

// Guard knows which namespaces are off limits and checks that a namespace
// really belongs to the expected container before anything enters it.
type Guard struct {
	host *Handle // nil when the kernel (AppArmor) does not let us open it
	self *Handle
	// procRoot is "/proc"; tests may point it elsewhere.
	procRoot string
}

// NewGuard opens the daemon's own network namespace and, if permitted, the
// host's (PID 1 with pid: host). Under AppArmor's docker-default profile
// opening /proc/1/ns/net is denied; HostKnown then reports false and Open
// relies on the address check alone.
func NewGuard() (*Guard, error) {
	self, err := open("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("open own netns: %w", err)
	}
	g := &Guard{self: self, procRoot: "/proc"}
	if host, err := open("/proc/1/ns/net"); err == nil {
		g.host = host
	}
	return g, nil
}

// HostKnown reports whether the host namespace could be identified.
func (g *Guard) HostKnown() bool { return g.host != nil }

// Close releases the guard's handles.
func (g *Guard) Close() error {
	var err error
	if g.host != nil {
		err = g.host.Close()
	}
	return errors.Join(err, g.self.Close())
}

// SelfTest verifies the daemon may call setns: it enters its own namespace.
func (g *Guard) SelfTest() error {
	return run(g.self, func() error { return nil })
}

// Open opens the network namespace of pid and refuses it unless it is
// provably a container's:
//   - it is not the daemon's own namespace, nor the host's (when known);
//   - it holds one of the container's IPv4 addresses (read from
//     /proc/<pid>/net/fib_trie, without entering the namespace). The host
//     namespace never holds a container's bridge address.
//
// A container without IPv4 addresses is refused if the host is unknown.
// Callers must still confirm afterwards that pid belongs to the container.
func (g *Guard) Open(pid int, ips []netip.Addr) (*Handle, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("invalid pid %d: %w", pid, ErrForbidden)
	}
	h, err := open(fmt.Sprintf("%s/%d/ns/net", g.procRoot, pid))
	if err != nil {
		return nil, err
	}
	if err := g.check(h, pid, ips); err != nil {
		_ = h.Close()
		return nil, err
	}
	return h, nil
}

func (g *Guard) check(h *Handle, pid int, ips []netip.Addr) error {
	if h.Same(g.self) || (g.host != nil && h.Same(g.host)) {
		return ErrForbidden
	}
	if len(ips) == 0 {
		if g.host == nil {
			return fmt.Errorf("container has no IPv4 address and the host netns is unknown, cannot prove the netns identity: %w", ErrForbidden)
		}
		return nil
	}
	f, err := os.Open(fmt.Sprintf("%s/%d/net/fib_trie", g.procRoot, pid))
	if err != nil {
		return fmt.Errorf("read local addresses: %w", err)
	}
	defer func() { _ = f.Close() }()
	local, err := LocalAddrs(f)
	if err != nil {
		return fmt.Errorf("read local addresses: %w", err)
	}
	for _, ip := range ips {
		if local[ip] {
			return nil
		}
	}
	return fmt.Errorf("netns of pid %d does not hold the container's addresses %v: %w", pid, ips, ErrForbidden)
}

// Do runs fn on an OS thread switched into h. Sockets created by fn stay in
// that namespace after Do returns. The thread is never returned to the Go
// scheduler: it exits with the goroutine, so no other goroutine can ever run
// in the wrong namespace.
func (g *Guard) Do(h *Handle, fn func() error) error {
	if h.Same(g.host) || h.Same(g.self) {
		return ErrForbidden
	}
	return run(h, fn)
}

func run(h *Handle, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		// Deliberately no UnlockOSThread: the thread dies with the goroutine.
		runtime.LockOSThread()
		if err := unix.Setns(h.Fd(), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("setns: %w", err)
			return
		}
		errc <- fn()
	}()
	return <-errc
}
