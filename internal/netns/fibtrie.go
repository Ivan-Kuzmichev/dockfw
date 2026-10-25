package netns

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// LocalAddrs parses /proc/<pid>/net/fib_trie and returns the IPv4 addresses
// configured on the namespace's interfaces (the "/32 host LOCAL" leaves):
//
//	|-- 172.19.0.2
//	   /32 host LOCAL
func LocalAddrs(r io.Reader) (map[netip.Addr]bool, error) {
	out := map[netip.Addr]bool{}
	var last netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "|-- "); ok {
			last, _ = netip.ParseAddr(rest)
			continue
		}
		if last.IsValid() && strings.HasPrefix(line, "/32 host LOCAL") {
			out[last] = true
		}
	}
	return out, sc.Err()
}
