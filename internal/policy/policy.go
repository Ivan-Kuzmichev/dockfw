package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// Policy is everything needed to render the nftables table of one container.
// Resolved domain addresses are not part of it: they are dynamic set
// elements managed by the resolver.
type Policy struct {
	Container string
	// Locked means the container's own allow.* and inbound labels are ignored
	// (invalid labels, or an unlabeled container under FW_UNLABELED=deny).
	// Symmetric InPeers still apply.
	Locked     bool
	LockReason string
	Mode       Mode
	Internet   bool
	Peers      []netip.Addr
	InPeers    []netip.Addr
	CIDRs      []netip.Prefix
	Domains    []string
	Inbound    []Inbound
	// Private is the IPv4 "not internet" list used when Internet is true.
	Private []netip.Prefix
}

// Text is the canonical, human-readable form of the policy. It is used for
// golden tests, debug logs and the hash.
func (p Policy) Text() string {
	var b strings.Builder
	line := func(key string, values ...string) {
		if len(values) == 0 {
			values = []string{"-"}
		}
		fmt.Fprintf(&b, "%-9s %s\n", key, strings.Join(values, " "))
	}
	yesNo := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}

	line("container", p.Container)
	if p.Locked {
		line("locked", "yes", "("+p.LockReason+")")
	} else {
		line("locked", "no")
	}
	line("mode", string(p.Mode))
	line("internet", yesNo(p.Internet))
	line("peers", strs(p.Peers)...)
	line("in-peers", strs(p.InPeers)...)
	line("cidrs", strs(p.CIDRs)...)
	line("domains", p.Domains...)
	line("inbound", strs(p.Inbound)...)
	line("private", strs(p.Private)...)
	return b.String()
}

// Hash identifies the policy; any change to it changes the hash.
func (p Policy) Hash() string {
	sum := sha256.Sum256([]byte(p.Text()))
	return hex.EncodeToString(sum[:8])
}

func strs[T fmt.Stringer](items []T) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.String()
	}
	return out
}
