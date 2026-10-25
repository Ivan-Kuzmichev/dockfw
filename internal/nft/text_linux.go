//go:build linux

package nft

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

// Text renders the ruleset in nft syntax, for debug logs.
func (rs *Ruleset) Text() string { return rs.render(false) }

// Dump is Text plus, under every rule, the netlink expressions actually sent
// to the kernel (in the style of nft --debug=netlink). Golden tests use it so
// that any change in generation shows up in the diff.
func (rs *Ruleset) Dump() string { return rs.render(true) }

func (rs *Ruleset) render(withExprs bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	for _, s := range rs.sets {
		var flags []string
		if s.interval {
			flags = append(flags, "interval")
		}
		if s.timeout {
			flags = append(flags, "timeout")
		}
		fmt.Fprintf(&b, "  set %s { type ipv4_addr;", s.name)
		if len(flags) > 0 {
			fmt.Fprintf(&b, " flags %s;", strings.Join(flags, ","))
		}
		if len(s.text) > 0 {
			fmt.Fprintf(&b, " elements = { %s };", strings.Join(s.text, ", "))
		}
		b.WriteString(" }\n")
	}
	for _, c := range rs.chains {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority filter; policy drop;\n", c.name, c.name)
		for _, r := range c.rules {
			fmt.Fprintf(&b, "    %s", r.text)
			if r.userData != nil {
				fmt.Fprintf(&b, " comment %q", commentPrefix+rs.Hash)
			}
			b.WriteString("\n")
			if withExprs {
				for _, e := range r.exprs {
					fmt.Fprintf(&b, "      %s\n", formatExpr(e))
				}
			}
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

var metaKeys = map[expr.MetaKey]string{
	expr.MetaKeyOIFNAME: "oifname",
	expr.MetaKeyIIFNAME: "iifname",
	expr.MetaKeyNFPROTO: "nfproto",
	expr.MetaKeyL4PROTO: "l4proto",
}

var cmpOps = map[expr.CmpOp]string{expr.CmpOpEq: "eq", expr.CmpOpNeq: "neq"}

var payloadBases = map[expr.PayloadBase]string{
	expr.PayloadBaseNetworkHeader:   "network",
	expr.PayloadBaseTransportHeader: "transport",
}

func formatExpr(e expr.Any) string {
	switch e := e.(type) {
	case *expr.Meta:
		return fmt.Sprintf("[ meta load %s => reg %d ]", metaKeys[e.Key], e.Register)
	case *expr.Cmp:
		return fmt.Sprintf("[ cmp %s reg %d 0x%s ]", cmpOps[e.Op], e.Register, hex.EncodeToString(e.Data))
	case *expr.Ct:
		return fmt.Sprintf("[ ct load state => reg %d ]", e.Register)
	case *expr.Bitwise:
		return fmt.Sprintf("[ bitwise reg %d = ( reg %d & 0x%s ) ^ 0x%s ]", e.DestRegister, e.SourceRegister, hex.EncodeToString(e.Mask), hex.EncodeToString(e.Xor))
	case *expr.Payload:
		return fmt.Sprintf("[ payload load %db @ %s header + %d => reg %d ]", e.Len, payloadBases[e.Base], e.Offset, e.DestRegister)
	case *expr.Lookup:
		return fmt.Sprintf("[ lookup reg %d set %s id %d ]", e.SourceRegister, e.SetName, e.SetID)
	case *expr.Verdict:
		switch e.Kind {
		case expr.VerdictAccept:
			return "[ immediate reg 0 accept ]"
		case expr.VerdictDrop:
			return "[ immediate reg 0 drop ]"
		}
		return fmt.Sprintf("[ immediate reg 0 verdict %d ]", e.Kind)
	case *expr.Reject:
		return fmt.Sprintf("[ reject type %d code %d ]", e.Type, e.Code)
	case *expr.Log:
		return fmt.Sprintf("[ log prefix %q ]", e.Data)
	case *expr.Counter:
		return "[ counter ]"
	}
	return fmt.Sprintf("[ %T ]", e)
}
