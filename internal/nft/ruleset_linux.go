//go:build linux

package nft

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
)

// TableName is the only table dockfw ever creates or deletes.
const TableName = "dockfw"

// Set names.
const (
	setPeers    = "peers4"
	setCIDRs    = "cidrs4"
	setDomains  = "domains4"
	setInPeers  = "in_peers4"
	setPrivate  = "private4"
	chainOutput = "output"
	chainInput  = "input"
)

// commentPrefix marks the first output rule with the policy hash so that
// reconcile can tell which policy a table was built from.
const commentPrefix = "dockfw policy "

// DomainElem is a resolved domain address and how long it stays allowed.
type DomainElem struct {
	Addr    netip.Addr
	Timeout time.Duration
}

// Options tweaks rendering.
type Options struct {
	// RejectAsDrop replaces "reject with icmpx" by "drop" for kernels that
	// lack nft_reject_inet.
	RejectAsDrop bool
}

type setSpec struct {
	name     string
	interval bool
	timeout  bool
	content
}

// content is a set's elements plus their text form.
type content struct {
	elems []nftables.SetElement
	text  []string
}

type ruleSpec struct {
	text     string
	exprs    []expr.Any
	userData []byte
}

type chainSpec struct {
	name  string
	hook  *nftables.ChainHook
	rules []ruleSpec
}

// Ruleset is the complete inet dockfw table for one container, ready to be
// applied atomically.
type Ruleset struct {
	Hash   string
	sets   []setSpec
	chains []chainSpec
}

// Build renders a policy (plus current domain addresses) into a Ruleset.
func Build(p policy.Policy, domains []DomainElem, opt Options) *Ruleset {
	rs := &Ruleset{Hash: p.Hash()}
	b := builder{rs: rs, p: p, opt: opt}

	b.addSet(setSpec{name: setPeers}, addrElems(p.Peers))
	b.addSet(setSpec{name: setCIDRs, interval: true}, intervalElems(p.CIDRs))
	b.addSet(setSpec{name: setDomains, timeout: true}, domainElems(domains))
	b.addSet(setSpec{name: setInPeers}, addrElems(p.InPeers))
	if p.Internet {
		b.addSet(setSpec{name: setPrivate, interval: true}, intervalElems(p.Private))
	}

	out := chainSpec{name: chainOutput, hook: nftables.ChainHookOutput}
	out.rules = append(out.rules,
		ruleSpec{
			text:     `oif "lo" accept`,
			exprs:    concat(ifname(expr.MetaKeyOIFNAME, "lo"), accept()),
			userData: userdata.AppendString(nil, userdata.TypeComment, commentPrefix+rs.Hash),
		},
		ruleSpec{text: "ct state established,related accept", exprs: concat(ctEstablished(), accept())},
		b.deny("meta nfproto ipv6", nfproto(unix.NFPROTO_IPV6)),
		ruleSpec{text: "ip daddr @" + setPeers + " accept", exprs: concat(b.lookup(16, setPeers), accept())},
		ruleSpec{text: "ip daddr @" + setCIDRs + " accept", exprs: concat(b.lookup(16, setCIDRs), accept())},
		ruleSpec{text: "ip daddr @" + setDomains + " accept", exprs: concat(b.lookup(16, setDomains), accept())},
	)
	if p.Internet {
		out.rules = append(out.rules,
			b.deny("ip daddr @"+setPrivate, b.lookup(16, setPrivate)),
			ruleSpec{text: "accept", exprs: accept()},
		)
	} else {
		out.rules = append(out.rules, b.deny(""))
	}

	in := chainSpec{name: chainInput, hook: nftables.ChainHookInput}
	in.rules = append(in.rules,
		ruleSpec{text: `iif "lo" accept`, exprs: concat(ifname(expr.MetaKeyIIFNAME, "lo"), accept())},
		ruleSpec{text: "ct state established,related accept", exprs: concat(ctEstablished(), accept())},
		ruleSpec{text: "ip saddr @" + setInPeers + " accept", exprs: concat(b.lookup(12, setInPeers), accept())},
	)
	for _, rule := range p.Inbound {
		in.rules = append(in.rules, inboundRules(rule)...)
	}
	in.rules = append(in.rules, b.deny(""))

	rs.chains = []chainSpec{out, in}
	return rs
}

type builder struct {
	rs  *Ruleset
	p   policy.Policy
	opt Options
}

func (b *builder) addSet(s setSpec, c content) {
	s.content = c
	b.rs.sets = append(b.rs.sets, s)
}

// setID returns the batch-local ID of a set. IDs are set explicitly because
// google/nftables otherwise allocates them from an unsynchronised global.
func (b *builder) setID(name string) uint32 {
	for i, s := range b.rs.sets {
		if s.name == name {
			return uint32(i + 1)
		}
	}
	panic("unknown set " + name)
}

// lookup matches the IPv4 address at offset (12 = saddr, 16 = daddr) against
// a named set.
func (b *builder) lookup(offset uint32, set string) []expr.Any {
	return concat(
		nfproto(unix.NFPROTO_IPV4),
		[]expr.Any{
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: set, SetID: b.setID(set)},
		},
	)
}

// deny is a reject (enforce), drop (no icmpx support) or log+accept (audit)
// after an optional match.
func (b *builder) deny(matchText string, match ...[]expr.Any) ruleSpec {
	var verdictText string
	var verdict []expr.Any
	switch {
	case b.p.Mode == policy.ModeAudit:
		prefix := logPrefix(b.p.Container)
		verdictText = fmt.Sprintf("counter log prefix %q accept", prefix)
		verdict = []expr.Any{&expr.Counter{}, &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(prefix)}, &expr.Verdict{Kind: expr.VerdictAccept}}
	case b.opt.RejectAsDrop:
		verdictText = "counter drop"
		verdict = []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}
	default:
		verdictText = "counter reject with icmpx type admin-prohibited"
		verdict = []expr.Any{&expr.Counter{}, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}}
	}
	text := verdictText
	if matchText != "" {
		text = matchText + " " + verdictText
	}
	return ruleSpec{text: text, exprs: concat(append(match, verdict)...)}
}

// logPrefix is "dockfw <name> ", trimmed to the kernel limit (127 bytes plus
// NUL) and stripped of anything but safe characters.
func logPrefix(name string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x80 && (r == '-' || r == '_' || r == '.' || r == '/' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return r
		}
		return '_'
	}, name)
	const maxName = 127 - len("dockfw  ")
	if len(clean) > maxName {
		clean = clean[:maxName]
	}
	return "dockfw " + clean + " "
}

func inboundRules(in policy.Inbound) []ruleSpec {
	protos := []policy.Proto{in.Proto}
	if in.Proto == policy.ProtoAny {
		protos = []policy.Proto{policy.ProtoTCP, policy.ProtoUDP}
	}
	var out []ruleSpec
	for _, proto := range protos {
		var text []string
		var exprs [][]expr.Any
		if !in.Any {
			text = append(text, "ip saddr "+in.Source.String())
			exprs = append(exprs, saddrPrefix(in.Source))
		}
		l4 := byte(unix.IPPROTO_TCP)
		if proto == policy.ProtoUDP {
			l4 = unix.IPPROTO_UDP
		}
		text = append(text, fmt.Sprintf("meta l4proto %s th dport %d accept", proto, in.Port))
		exprs = append(exprs,
			[]expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(in.Port)},
			},
			accept(),
		)
		out = append(out, ruleSpec{text: strings.Join(text, " "), exprs: concat(exprs...)})
	}
	return out
}

// saddrPrefix matches an IPv4 source prefix. /0 only checks the family.
func saddrPrefix(p netip.Prefix) []expr.Any {
	out := nfproto(unix.NFPROTO_IPV4)
	if p.Bits() == 0 {
		return out
	}
	out = append(out, &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4})
	if p.Bits() < 32 {
		m := make([]byte, 4)
		for i := 0; i < p.Bits(); i++ {
			m[i/8] |= 0x80 >> (i % 8)
		}
		out = append(out, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: m, Xor: make([]byte, 4)})
	}
	a := p.Masked().Addr().As4()
	return append(out, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a[:]})
}

func nfproto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func ifname(key expr.MetaKey, name string) []expr.Any {
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

func ctEstablished() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

func accept() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}} }

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func addrElems(addrs []netip.Addr) content {
	var c content
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		k := a.As4()
		c.elems = append(c.elems, nftables.SetElement{Key: k[:]})
		c.text = append(c.text, a.String())
	}
	return c
}

func domainElems(domains []DomainElem) content {
	ds := slices.Clone(domains)
	slices.SortFunc(ds, func(a, b DomainElem) int { return a.Addr.Compare(b.Addr) })
	var c content
	for _, d := range ds {
		if !d.Addr.Is4() || d.Timeout <= 0 {
			continue
		}
		timeout := d.Timeout.Truncate(time.Second)
		if timeout < time.Second {
			timeout = time.Second
		}
		k := d.Addr.As4()
		c.elems = append(c.elems, nftables.SetElement{Key: k[:], Timeout: timeout})
		c.text = append(c.text, fmt.Sprintf("%s timeout %s", d.Addr, timeout))
	}
	return c
}

// intervalElems converts prefixes to the start/end element pairs an interval
// set needs, merging overlapping and adjacent ranges.
func intervalElems(prefixes []netip.Prefix) content {
	type rng struct{ lo, hi uint32 }
	var rs []rng
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		lo := u32(p.Addr())
		hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
		rs = append(rs, rng{lo, hi})
	}
	slices.SortFunc(rs, func(a, b rng) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	var merged []rng
	for _, r := range rs {
		if n := len(merged); n > 0 && uint64(r.lo) <= uint64(merged[n-1].hi)+1 {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}

	var c content
	for _, r := range merged {
		c.elems = append(c.elems, nftables.SetElement{Key: be32(r.lo)})
		if r.hi != ^uint32(0) {
			c.elems = append(c.elems, nftables.SetElement{Key: be32(r.hi + 1), IntervalEnd: true})
		}
		c.text = append(c.text, fmt.Sprintf("%s-%s", addr(r.lo), addr(r.hi)))
	}
	return c
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func be32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func addr(v uint32) netip.Addr { return netip.AddrFrom4([4]byte(be32(v))) }
