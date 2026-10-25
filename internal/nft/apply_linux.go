//go:build linux

package nft

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/userdata"
)

// ErrMissing means the dockfw table is not present in the namespace.
var ErrMissing = errors.New("table inet dockfw is missing")

// ErrDrift means the table exists but does not match the expected ruleset.
var ErrDrift = errors.New("table inet dockfw does not match the expected policy")

func conn(nsFd int) (*nftables.Conn, error) {
	// fd 0 would make the library use the daemon's own namespace.
	if nsFd <= 0 {
		return nil, fmt.Errorf("invalid netns fd %d", nsFd)
	}
	return nftables.New(nftables.WithNetNSFd(nsFd))
}

// Apply atomically replaces the inet dockfw table in the namespace behind
// nsFd with rs. Nothing outside that table is touched.
func Apply(nsFd int, rs *Ruleset) error {
	c, err := conn(nsFd)
	if err != nil {
		return err
	}

	table := &nftables.Table{Name: TableName, Family: nftables.TableFamilyINet}
	// "add" is a no-op if the table exists, so the delete never fails; the
	// second add recreates it empty. All of this is one netlink batch.
	c.AddTable(table)
	c.DelTable(table)
	c.AddTable(table)

	for i, s := range rs.sets {
		set := &nftables.Set{
			Table:      table,
			ID:         uint32(i + 1),
			Name:       s.name,
			KeyType:    nftables.TypeIPAddr,
			Interval:   s.interval,
			HasTimeout: s.timeout,
		}
		if err := c.AddSet(set, s.elems); err != nil {
			return fmt.Errorf("set %s: %w", s.name, err)
		}
	}

	drop := nftables.ChainPolicyDrop
	for _, cs := range rs.chains {
		chain := c.AddChain(&nftables.Chain{
			Name:     cs.name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  cs.hook,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &drop,
		})
		for _, r := range cs.rules {
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: r.exprs, UserData: r.userData})
		}
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables transaction: %w", err)
	}
	return nil
}

// Verify checks that the namespace holds the table built from rs: the table
// and both chains exist, each chain has the expected number of rules, and the
// first output rule carries the policy hash.
func Verify(nsFd int, rs *Ruleset) error {
	c, err := conn(nsFd)
	if err != nil {
		return err
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == TableName {
			table = t
		}
	}
	if table == nil {
		return ErrMissing
	}

	for _, cs := range rs.chains {
		rules, err := c.GetRules(table, &nftables.Chain{Name: cs.name, Table: table})
		if err != nil {
			return fmt.Errorf("%w: chain %s: %v", ErrDrift, cs.name, err)
		}
		if len(rules) != len(cs.rules) {
			return fmt.Errorf("%w: chain %s has %d rules, want %d", ErrDrift, cs.name, len(rules), len(cs.rules))
		}
		if cs.name == chainOutput {
			comment, _ := userdata.GetString(rules[0].UserData, userdata.TypeComment)
			if want := commentPrefix + rs.Hash; strings.TrimRight(comment, "\x00") != want {
				return fmt.Errorf("%w: policy comment %q, want %q", ErrDrift, comment, want)
			}
		}
	}
	return nil
}
