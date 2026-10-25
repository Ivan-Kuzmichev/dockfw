package docker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"github.com/Ivan-Kuzmichev/dockfw/internal/policy"
)

// ErrNotRunning is returned by Inspect for containers that are gone or not
// running.
var ErrNotRunning = errors.New("container is not running")

// Info is what the daemon needs to know about a running container.
type Info struct {
	policy.Container
	Pid int
	// NetworkMode is HostConfig.NetworkMode: "host", "none", "container:<id>",
	// "bridge" or a network name.
	NetworkMode string
	CapAdd      []string
	Privileged  bool
}

// HostNetwork reports network_mode: host.
func (i *Info) HostNetwork() bool { return i.NetworkMode == "host" }

// NoNetwork reports network_mode: none.
func (i *Info) NoNetwork() bool { return i.NetworkMode == "none" }

// SharedNetwork reports network_mode: container:<id> (the namespace belongs
// to another container).
func (i *Info) SharedNetwork() bool { return strings.HasPrefix(i.NetworkMode, "container:") }

// HasNetAdmin reports whether the container can rewrite its own firewall.
func (i *Info) HasNetAdmin() bool {
	return i.Privileged || slices.ContainsFunc(i.CapAdd, func(c string) bool {
		c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		return c == "NET_ADMIN" || c == "ALL"
	})
}

// EventKind is the kind of a relevant Docker event.
type EventKind int

const (
	// EventStart: a container started (its netns is new).
	EventStart EventKind = iota
	// EventDie: a container stopped.
	EventDie
	// EventNetwork: a container was connected to or disconnected from a
	// network; its IPs changed.
	EventNetwork
)

// Event is a relevant Docker event.
type Event struct {
	Kind        EventKind
	ContainerID string
}

// Client is the small slice of the Docker API the daemon uses: list, inspect,
// events. That is all a socket proxy has to allow.
type Client struct {
	c *client.Client
}

// New connects using DOCKER_HOST and friends (unix socket by default, tcp://
// for a socket proxy).
func New() (*Client, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Ping checks that the API is reachable.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.c.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	return err
}

// Close releases the client.
func (c *Client) Close() error { return c.c.Close() }

// ListRunning returns the IDs of all running containers.
func (c *Client) ListRunning(ctx context.Context) ([]string, error) {
	res, err := c.c.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		ids = append(ids, it.ID)
	}
	return ids, nil
}

// Inspect returns the state of a running container, or ErrNotRunning.
func (c *Client) Inspect(ctx context.Context, id string) (*Info, error) {
	res, err := c.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if errdefs.IsNotFound(err) {
		return nil, ErrNotRunning
	}
	if err != nil {
		return nil, err
	}
	r := res.Container
	if r.State == nil || !r.State.Running || r.State.Pid <= 0 {
		return nil, ErrNotRunning
	}

	info := &Info{
		Container: policy.Container{
			ID:   r.ID,
			Name: strings.TrimPrefix(r.Name, "/"),
		},
		Pid: r.State.Pid,
	}
	if r.Config != nil {
		info.Labels = r.Config.Labels
	}
	if r.HostConfig != nil {
		info.NetworkMode = string(r.HostConfig.NetworkMode)
		info.CapAdd = r.HostConfig.CapAdd
		info.Privileged = r.HostConfig.Privileged
	}
	if r.NetworkSettings != nil {
		for name, ep := range r.NetworkSettings.Networks {
			info.Networks = append(info.Networks, name)
			if ep != nil && ep.IPAddress.IsValid() && ep.IPAddress.Unmap().Is4() {
				info.IPs = append(info.IPs, ep.IPAddress.Unmap())
			}
		}
	}
	slices.Sort(info.Networks)
	slices.SortFunc(info.IPs, netip.Addr.Compare)
	return info, nil
}

// Events streams container start/die and network connect/disconnect events
// until ctx is cancelled or the stream fails (the error channel then yields
// one error). The caller must resync after a failure.
func (c *Client) Events(ctx context.Context) (<-chan Event, <-chan error) {
	filters := client.Filters{}.
		Add("type", string(events.ContainerEventType), string(events.NetworkEventType)).
		Add("event", string(events.ActionStart), string(events.ActionDie), string(events.ActionConnect), string(events.ActionDisconnect))
	res := c.c.Events(ctx, client.EventsListOptions{Filters: filters})

	out := make(chan Event)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case err := <-res.Err:
				if err == nil {
					err = errors.New("event stream closed")
				}
				errc <- fmt.Errorf("docker events: %w", err)
				return
			case m := <-res.Messages:
				ev, ok := convert(m)
				if !ok {
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					errc <- ctx.Err()
					return
				}
			}
		}
	}()
	return out, errc
}

func convert(m events.Message) (Event, bool) {
	switch {
	case m.Type == events.ContainerEventType && m.Action == events.ActionStart:
		return Event{Kind: EventStart, ContainerID: m.Actor.ID}, true
	case m.Type == events.ContainerEventType && m.Action == events.ActionDie:
		return Event{Kind: EventDie, ContainerID: m.Actor.ID}, true
	case m.Type == events.NetworkEventType && (m.Action == events.ActionConnect || m.Action == events.ActionDisconnect):
		if id := m.Actor.Attributes["container"]; id != "" {
			return Event{Kind: EventNetwork, ContainerID: id}, true
		}
	}
	return Event{}, false
}
