//go:build linux

package netns

import (
	"errors"
	"fmt"
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

// Guard knows which namespaces are off limits.
type Guard struct {
	host *Handle
	self *Handle
}

// NewGuard opens the host (PID 1) and own network namespaces.
func NewGuard() (*Guard, error) {
	host, err := open("/proc/1/ns/net")
	if err != nil {
		return nil, fmt.Errorf("open host netns: %w", err)
	}
	self, err := open("/proc/self/ns/net")
	if err != nil {
		_ = host.Close()
		return nil, fmt.Errorf("open own netns: %w", err)
	}
	return &Guard{host: host, self: self}, nil
}

// Close releases the guard's handles.
func (g *Guard) Close() error {
	return errors.Join(g.host.Close(), g.self.Close())
}

// SelfTest verifies the daemon may call setns: it enters its own namespace.
func (g *Guard) SelfTest() error {
	return run(g.self, func() error { return nil })
}

// Open opens the network namespace of pid and refuses forbidden ones.
func (g *Guard) Open(pid int) (*Handle, error) {
	if pid <= 1 {
		return nil, fmt.Errorf("invalid pid %d: %w", pid, ErrForbidden)
	}
	h, err := open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, err
	}
	if h.Same(g.host) || h.Same(g.self) {
		_ = h.Close()
		return nil, ErrForbidden
	}
	return h, nil
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
