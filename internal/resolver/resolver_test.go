package resolver

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Ivan-Kuzmichev/dockfw/internal/config"
)

func TestPublic(t *testing.T) {
	private, err := config.ParsePrefixList(config.DefaultPrivateRanges)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"93.184.215.14":   true,
		"1.1.1.1":         true,
		"::ffff:8.8.8.8":  true, // IPv4-mapped is unmapped first
		"10.1.2.3":        false,
		"172.16.0.1":      false,
		"172.31.255.255":  false,
		"172.32.0.1":      true,
		"192.168.1.1":     false,
		"100.64.0.1":      false,
		"169.254.169.254": false,
		"127.0.0.1":       false,
		"127.1.2.3":       false,
		"0.0.0.0":         false,
		"0.1.2.3":         false,
		"224.0.0.1":       false,
		"240.0.0.1":       false,
		"255.255.255.255": false,
		"2606:4700::1111": false, // IPv6 not supported in v1
	} {
		if got := Public(netip.MustParseAddr(addr), private); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestTimeout(t *testing.T) {
	min := 5 * time.Minute
	for ttl, want := range map[time.Duration]time.Duration{
		0:                min,
		30 * time.Second: min,
		150 * time.Second: min,
		151 * time.Second: 302 * time.Second,
		time.Hour:         2 * time.Hour,
	} {
		if got := Timeout(ttl, min); got != want {
			t.Errorf("Timeout(%s) = %s, want %s", ttl, got, want)
		}
	}
}

func TestResolvable(t *testing.T) {
	if Resolvable("*.tmdb.org") || !Resolvable("api.themoviedb.org") {
		t.Error("Resolvable")
	}
}

type rr struct {
	cname string
	a     string
	ttl   uint32
}

func response(t *testing.T, id uint16, name string, rcode dnsmessage.RCode, truncated bool, rrs ...rr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: rcode, Truncated: truncated})
	n := dnsmessage.MustNewName(name)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	owner := n
	for _, r := range rrs {
		h := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: r.ttl}
		if r.cname != "" {
			target := dnsmessage.MustNewName(r.cname)
			must(b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: target}))
			owner = target
			continue
		}
		must(b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(r.a).As4()}))
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestQueryRoundTrip(t *testing.T) {
	q, err := BuildQuery(42, "api.themoviedb.org")
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(q); err != nil {
		t.Fatal(err)
	}
	if m.ID != 42 || !m.RecursionDesired || len(m.Questions) != 1 ||
		m.Questions[0].Name.String() != "api.themoviedb.org." || m.Questions[0].Type != dnsmessage.TypeA {
		t.Errorf("bad query: %+v", m)
	}
}

func TestParseResponse(t *testing.T) {
	const name = "image.tmdb.org."
	got, err := ParseResponse(7, "image.tmdb.org", response(t, 7, name, dnsmessage.RCodeSuccess, false,
		rr{cname: "cdn.example.net.", ttl: 300},
		rr{a: "13.224.1.1", ttl: 60},
		rr{a: "13.224.1.2", ttl: 30},
	))
	if err != nil {
		t.Fatal(err)
	}
	want := []Answer{{netip.MustParseAddr("13.224.1.1"), time.Minute}, {netip.MustParseAddr("13.224.1.2"), 30 * time.Second}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v want %v", got, want)
	}

	if _, err := ParseResponse(8, name, response(t, 7, name, dnsmessage.RCodeSuccess, false)); !errors.Is(err, errMismatch) {
		t.Errorf("wrong id: %v", err)
	}
	if _, err := ParseResponse(7, name, response(t, 7, name, dnsmessage.RCodeNameError, false)); err == nil {
		t.Error("NXDOMAIN must be an error")
	}
	if _, err := ParseResponse(7, name, response(t, 7, name, dnsmessage.RCodeSuccess, true)); !errors.Is(err, ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	if _, err := ParseResponse(7, "other.org", response(t, 7, name, dnsmessage.RCodeSuccess, false)); err == nil {
		t.Error("answer for another name accepted")
	}
	if _, err := ParseResponse(7, name, []byte{1, 2, 3}); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCache(t *testing.T) {
	c := NewCache()
	now := time.Unix(1_000_000, 0)
	a1, a2 := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")

	c.Add("x", []Answer{{a1, time.Hour}, {a2, 0}}, now, 5*time.Minute)
	els := c.Elements("x", now)
	if len(els) != 2 || els[0] != (Elem{a1, 2 * time.Hour}) || els[1] != (Elem{a2, 5 * time.Minute}) {
		t.Fatalf("elements = %v", els)
	}

	// A shorter TTL later never shrinks the grant.
	c.Add("x", []Answer{{a1, 0}}, now.Add(time.Minute), 5*time.Minute)
	if els := c.Elements("x", now.Add(time.Minute)); els[0].Timeout != 2*time.Hour-time.Minute {
		t.Errorf("expiry shrank: %v", els)
	}

	// Expired addresses disappear.
	if els := c.Elements("x", now.Add(10*time.Minute)); len(els) != 1 || els[0].Addr != a1 {
		t.Errorf("after expiry: %v", els)
	}
	if els := c.Elements("other", now); len(els) != 0 {
		t.Errorf("other container: %v", els)
	}
	c.Forget("x")
	if els := c.Elements("x", now); len(els) != 0 {
		t.Errorf("after forget: %v", els)
	}
}
