package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Compose labels used to resolve service references.
const (
	LabelComposeProject = "com.docker.compose.project"
	LabelComposeService = "com.docker.compose.service"
)

// Container is the subset of a running container's state the policy builder
// needs.
type Container struct {
	ID     string
	Name   string // without the leading "/"
	Labels map[string]string
	// IPs holds the container's IPv4 addresses on all its networks.
	IPs []netip.Addr
	// Networks holds the names of the networks the container is attached to.
	Networks []string
}

// Project returns the compose project label, if any.
func (c *Container) Project() string { return c.Labels[LabelComposeProject] }

// Service returns the compose service label, if any.
func (c *Container) Service() string { return c.Labels[LabelComposeService] }

// Options configures Build.
type Options struct {
	Prefix string
	// DenyUnlabeled locks containers without the enable label that are
	// attached to Network (FW_UNLABELED=deny).
	DenyUnlabeled bool
	Network       string
	// PrivateRanges is the full FW_PRIVATE_RANGES list; Build keeps the IPv4
	// part for the policy.
	PrivateRanges []netip.Prefix
}

// Result is the outcome of Build for one container.
type Result struct {
	Policy Policy
	// Managed is false when the daemon must leave the container alone.
	Managed bool
	// Errors explains why the policy is locked (invalid labels, ambiguous
	// references). Each error names the offending label.
	Errors []error
	// Warnings are non-fatal remarks worth logging.
	Warnings []string
	// Missing lists references that match no running container yet.
	Missing []string
}

// Build computes the policy of target given every running container (target
// may or may not be included in all). It is a pure function.
func Build(target *Container, all []*Container, opt Options) Result {
	res := Result{}
	spec, err := ParseLabels(opt.Prefix, target.Labels)

	pol := Policy{
		Container: target.Name,
		Mode:      ModeEnforce,
		Private:   ipv4Only(opt.PrivateRanges),
	}

	switch {
	case !spec.Enabled:
		if !opt.DenyUnlabeled || !slices.Contains(target.Networks, opt.Network) {
			if spec.HasLabels && err == nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("has %s* labels but %s%s is not true; container is not managed", opt.Prefix, opt.Prefix, keyEnable))
			}
			return res
		}
		pol.Locked, pol.LockReason = true, "unlabeled"
	case err != nil:
		res.Errors = append(res.Errors, err)
		pol.Locked, pol.LockReason = true, "invalid labels"
	default:
		peers, missing, rerr := resolveRefs(target, spec.Containers, all, opt.Prefix)
		if rerr != nil {
			res.Errors = append(res.Errors, rerr)
			pol.Locked, pol.LockReason = true, "invalid labels"
			break
		}
		res.Missing = missing
		pol.Mode = spec.Mode
		pol.Internet = spec.Internet
		pol.Peers = peers
		pol.CIDRs = spec.CIDRs
		pol.Domains = spec.Domains
		pol.Inbound = spec.Inbound
		for _, d := range spec.Domains {
			if strings.HasPrefix(d, "*.") {
				res.Warnings = append(res.Warnings, fmt.Sprintf("wildcard domain %q cannot be resolved (DNS cannot enumerate subdomains); list the exact names you need", d))
			}
		}
	}

	pol.InPeers = inPeers(target, all, opt.Prefix)
	res.Policy = pol
	res.Managed = true
	return res
}

// resolveRefs turns references into the sorted IPv4 addresses of the matching
// containers. References matching nothing are returned in missing; an
// ambiguous bare service name is an error.
func resolveRefs(self *Container, refs []Ref, all []*Container, prefix string) (peers []netip.Addr, missing []string, err error) {
	var errs []error
	for _, ref := range refs {
		matches, rerr := Match(ref, all)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("label %q: %w", prefix+keyContainers, rerr))
			continue
		}
		found := false
		for _, c := range matches {
			if c.ID == self.ID {
				continue
			}
			if len(c.IPs) > 0 {
				found = true
			}
			peers = append(peers, c.IPs...)
		}
		if !found {
			missing = append(missing, ref.String())
		}
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return sortedUnique(peers, netip.Addr.Compare), missing, nil
}

// Match resolves a reference against running containers (spec §6):
//  1. exact container name;
//  2. project/service via compose labels;
//  3. bare service name across all projects. Matches in more than one
//     project are ambiguous. Replicas of one service all match.
func Match(ref Ref, all []*Container) ([]*Container, error) {
	if ref.Project == "" {
		for _, c := range all {
			if c.Name == ref.Name {
				return []*Container{c}, nil
			}
		}
	}

	var out []*Container
	projects := map[string]bool{}
	for _, c := range all {
		if c.Service() != ref.Name {
			continue
		}
		if ref.Project != "" && c.Project() != ref.Project {
			continue
		}
		out = append(out, c)
		projects[c.Project()] = true
	}
	if len(projects) > 1 {
		names := make([]string, 0, len(projects))
		for p := range projects {
			names = append(names, p+"/"+ref.Name)
		}
		slices.Sort(names)
		return nil, fmt.Errorf("ambiguous reference %q matches %s; use project/service", ref.Name, strings.Join(names, ", "))
	}
	return out, nil
}

// inPeers collects the IPs of every enabled, valid container that lists
// target in its fw.allow.containers (symmetry: the connection is declared
// once, on the initiator side).
func inPeers(target *Container, all []*Container, prefix string) []netip.Addr {
	var out []netip.Addr
	for _, c := range all {
		if c.ID == target.ID || len(c.IPs) == 0 {
			continue
		}
		spec, err := ParseLabels(prefix, c.Labels)
		if err != nil || !spec.Enabled {
			continue
		}
		refersToTarget := false
		for _, ref := range spec.Containers {
			matches, err := Match(ref, all)
			if err != nil {
				// An ambiguous reference locks c, so it contributes nothing.
				refersToTarget = false
				break
			}
			for _, m := range matches {
				if m.ID == target.ID {
					refersToTarget = true
				}
			}
		}
		if refersToTarget {
			out = append(out, c.IPs...)
		}
	}
	return sortedUnique(out, netip.Addr.Compare)
}

func ipv4Only(prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}
