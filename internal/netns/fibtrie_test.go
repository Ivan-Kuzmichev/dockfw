package netns

import (
	"net/netip"
	"strings"
	"testing"
)

// Captured from a container on a user-defined bridge network.
const fibTrie = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.19.0.0/16 2 0 2
        +-- 172.19.0.0/30 2 0 2
           |-- 172.19.0.0
              /16 link UNICAST
           |-- 172.19.0.2
              /32 host LOCAL
        |-- 172.19.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 172.19.0.2
        /32 host LOCAL
`

func TestLocalAddrs(t *testing.T) {
	got, err := LocalAddrs(strings.NewReader(fibTrie))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1", "172.19.0.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, w := range want {
		if !got[netip.MustParseAddr(w)] {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	for _, not := range []string{"172.19.0.0", "172.19.255.255", "127.0.0.0"} {
		if got[netip.MustParseAddr(not)] {
			t.Errorf("%s is not a local address", not)
		}
	}
}
