package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Mode selects between enforcing and audit-only rules.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

// Proto is the transport protocol of an inbound rule.
type Proto string

const (
	// ProtoAny matches both TCP and UDP. It is used when fw.inbound omits the
	// protocol suffix.
	ProtoAny Proto = "tcp+udp"
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Inbound is one entry of fw.inbound.
type Inbound struct {
	// Any is true for the "any" source: no address match at all.
	Any bool
	// Source is the allowed IPv4 source prefix when Any is false.
	Source netip.Prefix
	Port   uint16
	Proto  Proto
}

func (in Inbound) String() string {
	src := "any"
	if !in.Any {
		src = in.Source.String()
	}
	return fmt.Sprintf("%s:%d/%s", src, in.Port, in.Proto)
}

// Ref is a reference from fw.allow.containers: a container name, a compose
// service, or project/service.
type Ref struct {
	Project string // empty unless the project/service form was used
	Name    string // container name or service name
}

func (r Ref) String() string {
	if r.Project != "" {
		return r.Project + "/" + r.Name
	}
	return r.Name
}

// Spec is what a container's own labels say, before looking at any other
// container.
type Spec struct {
	Enabled    bool
	Containers []Ref
	Domains    []string
	Internet   bool
	CIDRs      []netip.Prefix
	Inbound    []Inbound
	Mode       Mode
	// HasLabels reports whether any label with the prefix was present.
	HasLabels bool
}

// Label keys relative to the prefix.
const (
	keyEnable     = "enable"
	keyContainers = "allow.containers"
	keyDomains    = "allow.domains"
	keyInternet   = "allow.internet"
	keyCIDRs      = "allow.cidrs"
	keyInbound    = "inbound"
	keyMode       = "mode"
)

var (
	refRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$`)
	// One RFC 1123 hostname label.
	hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ParseLabels extracts the Spec from container labels. Every label under the
// prefix is validated; any error means the caller must lock the container.
// Even on error, Enabled reflects whether the container opted in, so that a
// broken fw.enable value still results in a locked (not ignored) container.
func ParseLabels(prefix string, labels map[string]string) (Spec, error) {
	spec := Spec{Mode: ModeEnforce}
	var errs []error
	fail := func(key string, err error) {
		errs = append(errs, fmt.Errorf("label %q: %w", prefix+key, err))
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	for _, full := range keys {
		spec.HasLabels = true
		key, value := strings.TrimPrefix(full, prefix), strings.TrimSpace(labels[full])
		switch key {
		case keyEnable:
			b, err := strconv.ParseBool(value)
			if err != nil {
				// Fail closed: a mistyped opt-in still opts in.
				spec.Enabled = true
				fail(key, fmt.Errorf("must be true or false, got %q", value))
				continue
			}
			spec.Enabled = b
		case keyContainers:
			for _, item := range splitList(value) {
				ref, err := parseRef(item)
				if err != nil {
					fail(key, err)
					continue
				}
				spec.Containers = append(spec.Containers, ref)
			}
		case keyDomains:
			for _, item := range splitList(value) {
				d, err := parseDomain(item)
				if err != nil {
					fail(key, err)
					continue
				}
				spec.Domains = append(spec.Domains, d)
			}
		case keyInternet:
			b, err := strconv.ParseBool(value)
			if err != nil {
				fail(key, fmt.Errorf("must be true or false, got %q", value))
				continue
			}
			spec.Internet = b
		case keyCIDRs:
			for _, item := range splitList(value) {
				p, err := parseIPv4Prefix(item)
				if err != nil {
					fail(key, err)
					continue
				}
				spec.CIDRs = append(spec.CIDRs, p)
			}
		case keyInbound:
			for _, item := range splitList(value) {
				in, err := parseInbound(item)
				if err != nil {
					fail(key, err)
					continue
				}
				spec.Inbound = append(spec.Inbound, in)
			}
		case keyMode:
			switch Mode(strings.ToLower(value)) {
			case ModeEnforce:
				spec.Mode = ModeEnforce
			case ModeAudit:
				spec.Mode = ModeAudit
			default:
				fail(key, fmt.Errorf("must be %q or %q, got %q", ModeEnforce, ModeAudit, value))
			}
		default:
			fail(key, errors.New("unknown label"))
		}
	}

	spec.Containers = sortedUnique(spec.Containers, func(a, b Ref) int { return strings.Compare(a.String(), b.String()) })
	spec.Domains = sortedUnique(spec.Domains, strings.Compare)
	spec.CIDRs = sortedUnique(spec.CIDRs, comparePrefix)
	spec.Inbound = sortedUnique(spec.Inbound, func(a, b Inbound) int { return strings.Compare(a.String(), b.String()) })

	return spec, errors.Join(errs...)
}

// splitList splits a comma-separated label value. Whitespace around items is
// ignored and empty items (e.g. a trailing comma) are dropped.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseRef(s string) (Ref, error) {
	if !refRe.MatchString(s) {
		return Ref{}, fmt.Errorf("invalid container reference %q", s)
	}
	if project, name, ok := strings.Cut(s, "/"); ok {
		return Ref{Project: project, Name: name}, nil
	}
	return Ref{Name: s}, nil
}

// parseDomain validates an RFC 1123 hostname with an optional leading "*.".
// The result is lower-cased and without a trailing dot.
func parseDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(s), ".")
	host := strings.TrimPrefix(d, "*.")
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	for _, l := range strings.Split(host, ".") {
		if !hostLabelRe.MatchString(l) {
			return "", fmt.Errorf("invalid domain %q", s)
		}
	}
	return d, nil
}

// parseIPv4Prefix accepts a CIDR or a bare address (as a host prefix).
func parseIPv4Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		addr, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q: only IPv4 is supported", s)
	}
	return p.Masked(), nil
}

// parseInbound parses "<source>:<port>[/tcp|/udp]" where source is "any", a
// CIDR or an address.
func parseInbound(s string) (Inbound, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return Inbound{}, fmt.Errorf("invalid inbound %q: want <cidr|any>:<port>[/tcp|/udp]", s)
	}
	src, portProto := s[:i], s[i+1:]

	in := Inbound{Proto: ProtoAny}
	portStr, proto, hasProto := strings.Cut(portProto, "/")
	if hasProto {
		switch Proto(strings.ToLower(proto)) {
		case ProtoTCP:
			in.Proto = ProtoTCP
		case ProtoUDP:
			in.Proto = ProtoUDP
		default:
			return Inbound{}, fmt.Errorf("invalid protocol in inbound %q: want tcp or udp", s)
		}
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Inbound{}, fmt.Errorf("invalid port in inbound %q: want 1-65535", s)
	}
	in.Port = uint16(port)

	if strings.EqualFold(src, "any") {
		in.Any = true
		return in, nil
	}
	p, err := parseIPv4Prefix(src)
	if err != nil {
		return Inbound{}, fmt.Errorf("invalid source in inbound %q: %w", s, err)
	}
	in.Source = p
	return in, nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

func sortedUnique[T comparable](s []T, cmp func(a, b T) int) []T {
	slices.SortFunc(s, cmp)
	return slices.Compact(s)
}
