package resolver

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Answer is one A record.
type Answer struct {
	Addr netip.Addr
	TTL  time.Duration
}

// Elem is an allowed address and how long it stays allowed.
type Elem struct {
	Addr    netip.Addr
	Timeout time.Duration
}

// alwaysBlocked is never accepted from DNS, whatever FW_PRIVATE_RANGES says.
var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Public reports whether a DNS answer may be added to the allow set. Private,
// loopback, link-local, multicast and reserved addresses are rejected to
// defeat DNS rebinding: a private address can only be allowed explicitly via
// fw.allow.cidrs.
func Public(a netip.Addr, private []netip.Prefix) bool {
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range slices.Concat(alwaysBlocked, private) {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Timeout is how long a resolved address stays in the set:
// max(TTL × 2, minimum).
func Timeout(ttl, minimum time.Duration) time.Duration {
	return max(2*ttl, minimum)
}

// Resolvable reports whether a domain from fw.allow.domains can be looked
// up. Wildcards cannot: DNS has no way to enumerate subdomains.
func Resolvable(domain string) bool { return !strings.HasPrefix(domain, "*.") }

// BuildQuery makes a recursive A query for name.
func BuildQuery(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

// ErrTruncated means the UDP answer was truncated and TCP should be used.
var ErrTruncated = errors.New("truncated DNS response")

// errMismatch means the message answers some other query.
var errMismatch = errors.New("mismatched DNS response")

// ParseResponse extracts the A records of a response to the query id/name.
// CNAME chains are followed implicitly: the resolver returns the final A
// records in the answer section.
func ParseResponse(id uint16, name string, b []byte) ([]Answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return nil, err
	}
	if h.ID != id || !h.Response {
		return nil, errMismatch
	}
	if h.Truncated {
		return nil, ErrTruncated
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS error %s", h.RCode)
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(q.Name.String(), strings.TrimSuffix(name, ".")+".") {
		return nil, errors.New("DNS response for another name")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []Answer
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if rh.Type != dnsmessage.TypeA || rh.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return nil, err
		}
		out = append(out, Answer{Addr: netip.AddrFrom4(a.A), TTL: time.Duration(rh.TTL) * time.Second})
	}
}

// Cache remembers resolved addresses per container until they expire.
type Cache struct {
	mu sync.Mutex
	m  map[string]map[netip.Addr]time.Time
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{m: map[string]map[netip.Addr]time.Time{}} }

// Add records addresses for a container. An address's expiry is only ever
// extended, so a short TTL in one answer never shrinks an earlier, longer
// grant.
func (c *Cache) Add(id string, answers []Answer, now time.Time, minimum time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.m[id]
	if m == nil {
		m = map[netip.Addr]time.Time{}
		c.m[id] = m
	}
	for _, a := range answers {
		exp := now.Add(Timeout(a.TTL, minimum))
		if exp.After(m[a.Addr]) {
			m[a.Addr] = exp
		}
	}
}

// Elements returns the unexpired addresses of a container with their
// remaining lifetime, and drops expired ones.
func (c *Cache) Elements(id string, now time.Time) []Elem {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Elem
	for addr, exp := range c.m[id] {
		left := exp.Sub(now)
		if left <= 0 {
			delete(c.m[id], addr)
			continue
		}
		out = append(out, Elem{Addr: addr, Timeout: left})
	}
	slices.SortFunc(out, func(a, b Elem) int { return a.Addr.Compare(b.Addr) })
	return out
}

// Forget drops everything known about a container.
func (c *Cache) Forget(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}
