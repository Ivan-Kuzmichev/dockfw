//go:build linux

package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/Ivan-Kuzmichev/dockfw/internal/netns"
)

// DockerDNS is Docker's embedded DNS server as seen from inside a container
// on a user-defined network.
const DockerDNS = "127.0.0.11:53"

// Lookuper resolves names from inside container network namespaces, so the
// answers match what the application gets from Docker's DNS.
type Lookuper struct {
	Guard   *netns.Guard
	Server  string        // default DockerDNS
	Timeout time.Duration // per query, default 2s
}

// Result is the outcome for one name.
type Result struct {
	Name    string
	Answers []Answer
	Err     error
}

// Lookup resolves every name in the netns of pid (which must hold one of
// ips). A failure for one name does not affect the others.
func (l *Lookuper) Lookup(ctx context.Context, pid int, ips []netip.Addr, names []string) ([]Result, error) {
	h, err := l.Guard.Open(pid, ips)
	if err != nil {
		return nil, err
	}
	defer func() { _ = h.Close() }()

	server := l.Server
	if server == "" {
		server = DockerDNS
	}
	timeout := l.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	// The socket is created on a thread inside the container netns and keeps
	// living there; all I/O below happens on ordinary goroutines.
	dial := func(network string) (net.Conn, error) {
		var conn net.Conn
		err := l.Guard.Do(h, func() error {
			var derr error
			conn, derr = net.DialTimeout(network, server, timeout)
			return derr
		})
		return conn, err
	}
	udp, err := dial("udp")
	if err != nil {
		return nil, fmt.Errorf("dns socket in container netns: %w", err)
	}
	defer func() { _ = udp.Close() }()

	results := make([]Result, 0, len(names))
	for _, name := range names {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		answers, err := queryUDP(udp, name, timeout)
		if errors.Is(err, ErrTruncated) {
			answers, err = queryTCP(dial, name, timeout)
		}
		results = append(results, Result{Name: name, Answers: answers, Err: err})
	}
	return results, nil
}

func queryUDP(conn net.Conn, name string, timeout time.Duration) ([]Answer, error) {
	var lastErr error
	for range 2 {
		id := uint16(rand.UintN(1 << 16))
		q, err := BuildQuery(id, name)
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, 1500)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			answers, err := ParseResponse(id, name, buf[:n])
			if errors.Is(err, errMismatch) {
				continue // a late answer to an earlier query
			}
			return answers, err
		}
	}
	return nil, lastErr
}

func queryTCP(dial func(string) (net.Conn, error), name string, timeout time.Duration) ([]Answer, error) {
	conn, err := dial("tcp")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	id := uint16(rand.UintN(1 << 16))
	q, err := BuildQuery(id, name)
	if err != nil {
		return nil, err
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := conn.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return ParseResponse(id, name, buf)
}
