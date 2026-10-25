//go:build integration

// Package integration runs the end-to-end scenarios of spec §11 against a
// real Docker engine: make integration (Linux or Docker Desktop).
package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	project = "dockfw-it"
	fillers = 20
	daemon  = "it-dockfw"
)

// labeled is every container the daemon must manage (fillers excluded).
var labeled = []string{"it-web", "it-a", "it-b", "it-c", "it-dom", "it-pub", "it-nopub", "it-bad", "it-audit", "it-unlabeled"}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func compose(args ...string) (string, error) {
	return run("docker", append([]string{"compose", "-f", "compose.yml"}, args...)...)
}

func TestMain(m *testing.M) {
	os.Exit(func() int {
		_, _ = compose("down", "-v", "--remove-orphans")
		if out, err := compose("--profile", "build-only", "build"); err != nil {
			fmt.Fprintln(os.Stderr, "build failed:", out)
			return 1
		}
		if out, err := compose("up", "-d", "--wait", "--scale", fmt.Sprintf("filler=%d", fillers)); err != nil {
			logs, _ := run("docker", "logs", daemon)
			fmt.Fprintln(os.Stderr, "compose up failed:", out, "\n--- daemon logs\n", logs)
			return 1
		}
		if os.Getenv("DOCKFW_IT_KEEP") == "" {
			defer func() { _, _ = compose("down", "-v", "--remove-orphans") }()
		}
		if err := waitApplied(labeled, 60*time.Second); err != nil {
			logs, _ := run("docker", "logs", daemon)
			fmt.Fprintln(os.Stderr, err, "\n", logs)
			return 1
		}
		code := m.Run()
		if code != 0 {
			logs, _ := run("docker", "logs", daemon)
			fmt.Fprintln(os.Stderr, "--- daemon logs\n", logs)
		}
		return code
	}())
}

type logLine struct {
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Msg       string    `json:"msg"`
	Container string    `json:"container"`
	Duration  string    `json:"duration"`
	Error     string    `json:"error"`
}

func daemonLogs() ([]logLine, error) {
	out, err := exec.Command("docker", "logs", daemon).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	var lines []logLine
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l logLine
		if json.Unmarshal(sc.Bytes(), &l) == nil {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

func mustLogs(t *testing.T) []logLine {
	t.Helper()
	lines, err := daemonLogs()
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

func waitApplied(names []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		lines, err := daemonLogs()
		if err != nil {
			return err
		}
		applied := map[string]bool{}
		for _, l := range lines {
			if l.Msg == "policy applied" {
				applied[l.Container] = true
			}
		}
		var missing []string
		for _, n := range names {
			if !applied[n] {
				missing = append(missing, n)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("policies not applied for %v", missing)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// curl reports whether ctr can fetch url within 3 seconds.
func curl(ctr, url string) bool {
	_, err := run("docker", "exec", ctr, "curl", "-sS", "-o", "/dev/null", "--max-time", "3", url)
	return err == nil
}

func ip(t *testing.T, ctr string) string {
	t.Helper()
	out, err := run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", ctr)
	if err != nil {
		t.Fatal(out)
	}
	return strings.Fields(out)[0]
}

func pid(t *testing.T, ctr string) string {
	t.Helper()
	out, err := run("docker", "inspect", "-f", "{{.State.Pid}}", ctr)
	if err != nil {
		t.Fatal(out)
	}
	return out
}

// hostNft runs nft inside the netns of ctr, from the host side.
func hostNft(t *testing.T, ctr string, args ...string) (string, error) {
	t.Helper()
	cmd := append([]string{"run", "--rm", "--privileged", "--pid", "host", "--network", "none", "dockfw-it-tools",
		"nsenter", "-t", pid(t, ctr), "-n", "nft"}, args...)
	return run("docker", cmd...)
}

func expect(t *testing.T, ctr, url string, want bool) {
	t.Helper()
	if got := curl(ctr, url); got != want {
		verb := map[bool]string{true: "reach", false: "NOT reach"}[want]
		t.Errorf("%s must %s %s", ctr, verb, url)
	}
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > timeout {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Since(start)
}

// gateway is the host's address on the fw network (it-hostsrv listens there).
func gateway(t *testing.T) string {
	t.Helper()
	gw, err := run("docker", "network", "inspect", "-f", "{{(index .IPAM.Config 0).Gateway}}", "dockfw-it-fw")
	if err != nil || gw == "" {
		t.Fatalf("gateway: %s %v", gw, err)
	}
	return gw
}

// §11.1
func TestInternetOnly(t *testing.T) {
	gw := gateway(t)
	expect(t, "it-othernet", "http://"+gw+":18999/", true) // sanity: the host listener works
	expect(t, "it-web", "https://1.1.1.1", true)
	expect(t, "it-web", "http://"+gw+":18999/", false)
	expect(t, "it-web", "http://"+ip(t, "it-c")+":8080/", false)
}

// §11.2
func TestContainersAndSymmetry(t *testing.T) {
	expect(t, "it-a", "http://b:8080/", true)
	expect(t, "it-b", "http://a:8080/", false)
	expect(t, "it-c", "http://a:8080/", false)
	expect(t, "it-c", "http://b:8080/", false)
	expect(t, "it-a", "http://c:8080/", false)
}

// §11.3
func TestDomains(t *testing.T) {
	eventually(t, "example.com reachable", 15*time.Second, func() bool { return curl("it-dom", "https://example.com") })
	expect(t, "it-dom", "https://1.1.1.1", false)
	expect(t, "it-dom", "https://github.com", false)
}

// §11.4
func TestInboundFromHost(t *testing.T) {
	hostCurl := func(port string) bool {
		_, err := run("docker", "run", "--rm", "--network", "host", "dockfw-it-tools",
			"curl", "-sS", "-o", "/dev/null", "--max-time", "3", "http://127.0.0.1:"+port+"/")
		return err == nil
	}
	if !hostCurl("18080") {
		t.Error("host must reach it-pub (fw.inbound 0.0.0.0/0:8080)")
	}
	if hostCurl("18081") {
		t.Error("host must NOT reach it-nopub (no fw.inbound)")
	}
}

// §11.5 and the "< 2 s reaction" acceptance criterion.
func TestRestartDependent(t *testing.T) {
	if out, err := run("docker", "restart", "-t", "0", "it-b"); err != nil {
		t.Fatal(out)
	}
	took := eventually(t, "a reaches restarted b", 5*time.Second, func() bool { return curl("it-a", "http://b:8080/") })
	t.Logf("a reached b %s after restart", took)
	if took > 2*time.Second {
		t.Errorf("reaction %s exceeds 2s", took)
	}
	expect(t, "it-b", "http://a:8080/", false)
}

// §11.6
func TestInvalidLabelLocks(t *testing.T) {
	expect(t, "it-bad", "https://1.1.1.1", false)
	expect(t, "it-bad", "http://b:8080/", false)
	found := false
	for _, l := range mustLogs(t) {
		if l.Level == "ERROR" && l.Container == "it-bad" && strings.Contains(l.Error, "fw.inbound") {
			found = true
		}
	}
	if !found {
		t.Error("no ERROR log naming it-bad and fw.inbound")
	}
}

// §11.7
func TestReconcileRestoresTable(t *testing.T) {
	if out, err := hostNft(t, "it-c", "delete", "table", "inet", "dockfw"); err != nil {
		t.Fatalf("delete table: %s", out)
	}
	eventually(t, "table restored", 10*time.Second, func() bool {
		_, err := hostNft(t, "it-c", "list", "table", "inet", "dockfw")
		return err == nil
	})
	expect(t, "it-c", "https://1.1.1.1", false)
}

// §11.8
func TestAuditMode(t *testing.T) {
	expect(t, "it-audit", "https://1.1.1.1", true)
	expect(t, "it-audit", "http://"+gateway(t)+":18999/", true) // the host: logged, not rejected
	out, err := hostNft(t, "it-audit", "list", "table", "inet", "dockfw")
	if err != nil || !strings.Contains(out, `log prefix "dockfw it-audit "`) {
		t.Errorf("audit table must log:\n%s", out)
	}
}

// §11.9
func TestUnlabeledDeny(t *testing.T) {
	expect(t, "it-unlabeled", "https://1.1.1.1", false)
	expect(t, "it-othernet", "https://1.1.1.1", true)
}

// §11.10 and "only inet dockfw is added, Docker DNS NAT untouched".
func TestDNSAndForeignTablesUntouched(t *testing.T) {
	for _, q := range []string{"b", "example.com"} {
		if out, err := run("docker", "exec", "it-a", "nslookup", q); err != nil {
			t.Errorf("nslookup %s in a protected container failed:\n%s", q, out)
		}
	}
	out, err := hostNft(t, "it-a", "list", "tables")
	if err != nil {
		t.Fatal(out)
	}
	for _, tbl := range strings.Split(out, "\n") {
		if tbl != "table inet dockfw" && tbl != "table ip nat" && tbl != "table ip6 nat" {
			t.Errorf("unexpected table in container netns: %q", tbl)
		}
	}
	if !strings.Contains(out, "table ip nat") || !strings.Contains(out, "table inet dockfw") {
		t.Errorf("want Docker's ip nat and inet dockfw, got:\n%s", out)
	}
	nat, _ := hostNft(t, "it-a", "list", "table", "ip", "nat")
	if !strings.Contains(nat, "DOCKER_OUTPUT") {
		t.Errorf("Docker DNS NAT missing:\n%s", nat)
	}
}

// Acceptance (§13): full pass over 30 containers < 5 s, one apply < 200 ms.
func TestPerformance(t *testing.T) {
	if out, err := run("docker", "restart", "-t", "1", daemon); err != nil {
		t.Fatal(out)
	}
	restarted := time.Now().UTC()
	var started time.Time
	eventually(t, "full pass after restart", 15*time.Second, func() bool {
		count := 0
		for _, l := range mustLogs(t) {
			if l.Time.Before(restarted.Add(-time.Second)) {
				continue
			}
			if l.Msg == "starting dockfw" {
				started, count = l.Time, 0
			}
			if l.Msg == "policy applied" && !started.IsZero() {
				count++
				if d, err := time.ParseDuration(l.Duration); err == nil && d > 200*time.Millisecond {
					t.Errorf("apply for %s took %s", l.Container, d)
				}
				if count >= len(labeled)+fillers {
					t.Logf("%d policies applied %s after start", count, l.Time.Sub(started))
					if l.Time.Sub(started) > 5*time.Second {
						t.Errorf("full pass took %s", l.Time.Sub(started))
					}
					return true
				}
			}
		}
		return false
	})
}

// Acceptance (§13): FROM scratch, single file, < 15 MB uncompressed.
func TestImage(t *testing.T) {
	id, err := run("docker", "create", "dockfw:it")
	if err != nil {
		t.Fatal(id)
	}
	defer func() { _, _ = run("docker", "rm", id) }()
	tarball, err := exec.Command("docker", "export", id).Output()
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range strings.Split(listTar(t, tarball), "\n") {
		// Docker adds empty mount points and /etc stubs to every container.
		if f != "" && !strings.HasSuffix(f, "/") && !strings.HasPrefix(f, "etc/") && !strings.HasPrefix(f, "dev/") && f != ".dockerenv" {
			files = append(files, f)
		}
	}
	t.Logf("image filesystem: %.1f MB, files %v", float64(len(tarball))/1e6, files)
	if len(files) != 1 || files[0] != "dockfw" {
		t.Errorf("image must contain only /dockfw, got %v", files)
	}
	if len(tarball) >= 15e6 {
		t.Errorf("image is %d bytes, want < 15 MB", len(tarball))
	}
}

func listTar(t *testing.T, b []byte) string {
	t.Helper()
	cmd := exec.Command("tar", "-tf", "-")
	cmd.Stdin = strings.NewReader(string(b))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
