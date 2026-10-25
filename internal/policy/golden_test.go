package policy

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// goldenCompare compares got with testdata/<name>.golden, rewriting the file
// when -update is set.
func goldenCompare(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s mismatch (run go test -update to accept)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

// The compose example from the spec (§3) plus a broken container.
func exampleContainers() []*Container {
	return []*Container{
		ctr("dublyarr", "media", "dublyarr", []string{"172.20.0.10"}, on(map[string]string{
			"fw.allow.containers": "qbittorrent,jackett",
			"fw.allow.domains":    "api.themoviedb.org,image.tmdb.org",
			"fw.inbound":          "192.168.1.0/24:3000",
		})),
		ctr("qbittorrent", "media", "qbittorrent", []string{"172.20.0.11"}, on(map[string]string{
			"fw.allow.internet": "true",
			"fw.inbound":        "192.168.1.0/24:8787,any:54890",
		})),
		ctr("jackett", "media", "jackett", []string{"172.20.0.12"}, on(map[string]string{
			"fw.allow.internet": "true",
			"fw.allow.cidrs":    "192.168.1.5",
			"fw.mode":           "audit",
		})),
		ctr("vaultwarden", "vault", "vaultwarden", []string{"172.20.0.13"}, on(map[string]string{
			"fw.inbound": "192.168.1.0/24:80/tcp",
		})),
		ctr("broken", "misc", "broken", []string{"172.20.0.14"}, on(map[string]string{
			"fw.allow.internet": "true",
			"fw.inbound":        "lan:80",
		})),
	}
}

func TestGoldenExample(t *testing.T) {
	all := exampleContainers()
	var b strings.Builder
	for _, c := range all {
		r := Build(c, all, opts())
		b.WriteString(r.Policy.Text())
		b.WriteString("hash      " + r.Policy.Hash() + "\n\n")
	}
	goldenCompare(t, "example", b.String())
}
