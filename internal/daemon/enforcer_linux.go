//go:build linux

package daemon

import (
	"github.com/Ivan-Kuzmichev/dockfw/internal/netns"
	"github.com/Ivan-Kuzmichev/dockfw/internal/nft"
)

// NetnsEnforcer is the real Enforcer: netns.Guard + nft.
type NetnsEnforcer struct {
	Guard *netns.Guard
}

// SelfTest checks that setns works at all.
func (e *NetnsEnforcer) SelfTest() error { return e.Guard.SelfTest() }

// Apply opens the namespace first and confirms the PID afterwards: once the
// fd is open it pins the namespace, so a confirmed PID means the fd is the
// container's namespace and not one of a recycled PID.
func (e *NetnsEnforcer) Apply(pid int, rs *nft.Ruleset, confirm func() error) error {
	h, err := e.Guard.Open(pid)
	if err != nil {
		// Most often the container has just exited; let confirm say so.
		if cerr := confirm(); cerr != nil {
			return cerr
		}
		return err
	}
	defer func() { _ = h.Close() }()
	if err := confirm(); err != nil {
		return err
	}
	return nft.Apply(h.Fd(), rs)
}

// Verify checks the table in the namespace of pid.
func (e *NetnsEnforcer) Verify(pid int, rs *nft.Ruleset) error {
	h, err := e.Guard.Open(pid)
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	return nft.Verify(h.Fd(), rs)
}
