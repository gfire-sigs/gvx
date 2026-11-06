// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package route

import (
	"encoding/binary"
	"errors"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Routing rule messages, attributes, and flags of include/uapi/linux/fib_rules.h.
const (
	fibRuleHdrSize = 12

	fraDst               = 1
	fraSrc               = 2
	fraIifname           = 3
	fraGoto              = 4
	fraPriority          = 6
	fraFwmark            = 10
	fraFlow              = 11
	fraTunID             = 12
	fraSuppressIfgroup   = 13
	fraSuppressPrefixlen = 14
	fraTable             = 15
	fraFwmask            = 16
	fraOifname           = 17
	fraPad               = 18
	fraL3mdev            = 19
	fraUIDRange          = 20
	fraProtocol          = 21
	fraIPProto           = 22
	fraSportRange        = 23
	fraDportRange        = 24

	fibRuleInvert      = 0x2
	fibRuleIifDetached = 0x8
	fibRuleOifDetached = 0x10

	// ifNameSize is IFNAMSIZ, the size of an interface name with its NUL.
	ifNameSize = 16
)

// rtaxMTU is RTAX_MTU, the MTU entry of RTA_METRICS.
const rtaxMTU = 2

// compatTable returns the rtm_table byte of a table identifier. A table above
// 255 shows RT_TABLE_COMPAT there, and RTA_TABLE holds the identifier.
func compatTable(table uint32) uint8 {
	switch {
	case table == 0:
		return linux.RT_TABLE_MAIN
	case table > 255:
		return linux.RT_TABLE_COMPAT
	}
	return uint8(table)
}

// ruleTableByte returns the table byte of a rule header. A rule that does
// not look up a table has table 0.
func ruleTableByte(table uint32) uint8 {
	if table > 255 {
		return linux.RT_TABLE_COMPAT
	}
	return uint8(table)
}

// tableOrMain returns the table identifier of a route, 0 resolved to main.
func tableOrMain(table uint32) uint32 {
	if table == 0 {
		return linux.RT_TABLE_MAIN
	}
	return table
}

// isRuleMessage reports whether the message type belongs to the routing rules.
func isRuleMessage(typ uint16) bool {
	return typ == linux.RTM_NEWRULE || typ == linux.RTM_DELRULE || typ == linux.RTM_GETRULE
}

// fibRuleHdr is struct fib_rule_hdr.
type fibRuleHdr struct {
	family, dstLen, srcLen, tos, table uint8
	action                             uint8
	flags                              uint32
}

func (h fibRuleHdr) bytes() []byte {
	b := make([]byte, fibRuleHdrSize)
	b[0], b[1], b[2], b[3], b[4] = h.family, h.dstLen, h.srcLen, h.tos, h.table
	b[7] = h.action
	binary.NativeEndian.PutUint32(b[8:], h.flags)
	return b
}

// parseRuleMessage returns the header and, when withAttrs is set, the
// attributes of a rule message. A dump request reads only the family: netlink
// libraries send struct ifinfomsg there, which is longer than struct
// fib_rule_hdr.
func parseRuleMessage(msg *nlmsg.Message, withAttrs bool) (fibRuleHdr, map[uint16]nlmsg.BytesView, bool) {
	buf := msg.Buffer()
	if !withAttrs {
		// fib_nl_dumprule reads no header. A caller with struct rtgenmsg, as
		// busybox sends, gives one byte of family.
		if len(buf) <= linux.NetlinkMessageHeaderSize {
			return fibRuleHdr{}, nil, false
		}
		return fibRuleHdr{family: buf[linux.NetlinkMessageHeaderSize]}, nil, true
	}
	if len(buf) < linux.NetlinkMessageHeaderSize+fibRuleHdrSize {
		return fibRuleHdr{}, nil, false
	}
	b := buf[linux.NetlinkMessageHeaderSize:]
	h := fibRuleHdr{
		family: b[0], dstLen: b[1], srcLen: b[2], tos: b[3], table: b[4], action: b[7],
		flags: binary.NativeEndian.Uint32(b[8:]),
	}
	attrs, ok := nlmsg.AttrsView(b[fibRuleHdrSize:]).Parse()
	return h, attrs, ok
}

// processRule answers RTM_NEWRULE, RTM_DELRULE, and RTM_GETRULE.
func (p *Protocol) processRule(_ context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	ns, ok := s.Stack().(*netstack.Stack)
	if !ok {
		return syserr.ErrNotSupported
	}
	hdr := msg.Header()
	h, attrs, ok := parseRuleMessage(msg, hdr.Type != linux.RTM_GETRULE)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	switch hdr.Type {
	case linux.RTM_GETRULE:
		if hdr.Flags&(linux.NLM_F_DUMP|linux.NLM_F_ROOT) == 0 {
			return syserr.ErrNotSupported
		}
		ms.Multi = true
		p.dumpRules(ns, h.family, ms)
		return nil
	case linux.RTM_NEWRULE:
		return newRule(ns, hdr.Flags, h, attrs)
	default:
		return deleteRule(ns, h, attrs)
	}
}

// ruleProtocol returns the network protocol of an address family, or false
// for a family that has no routing rules.
func ruleProtocol(family uint8) (tcpip.NetworkProtocolNumber, bool) {
	switch family {
	case linux.AF_INET:
		return header.IPv4ProtocolNumber, true
	case linux.AF_INET6:
		return header.IPv6ProtocolNumber, true
	}
	return 0, false
}

// ruleAttrs holds the attributes of a rule request after validation.
type ruleAttrs struct {
	proto     tcpip.NetworkProtocolNumber
	priority  *uint32
	table     uint32
	mark      *uint32
	markMask  *uint32
	gotoPrio  *uint32
	suppress  *int32
	protocol  *uint8
	iif, oif  *string
	src, dst  *tcpip.Address
	addrBytes int
}

// readRuleAttrs reads and checks the attributes that rules of this stack
// support. Linux accepts more matches: the interface group, the layer 3
// master device, the UID range, the IP protocol, the ports, and the tunnel
// ID. The stack has no value for them, so such a request fails with EOPNOTSUPP.
func readRuleAttrs(h fibRuleHdr, attrs map[uint16]nlmsg.BytesView) (ruleAttrs, *syserr.Error) {
	proto, ok := ruleProtocol(h.family)
	if !ok {
		return ruleAttrs{}, syserr.ErrNotSupported
	}
	ra := ruleAttrs{proto: proto, table: uint32(h.table), addrBytes: header.IPv4AddressSize}
	if h.family == linux.AF_INET6 {
		ra.addrBytes = header.IPv6AddressSize
	}
	for typ, v := range attrs {
		switch typ {
		case fraUIDRange, fraIPProto, fraSportRange, fraDportRange, fraTunID, fraSuppressIfgroup:
			return ruleAttrs{}, syserr.ErrNotSupported
		case fraL3mdev:
			if b, ok := v.Uint8(); !ok || b != 0 {
				return ruleAttrs{}, syserr.ErrNotSupported
			}
		case fraPriority, fraTable, fraFwmark, fraFwmask, fraGoto, fraSuppressPrefixlen:
			n, ok := v.Uint32()
			if !ok {
				return ruleAttrs{}, syserr.ErrInvalidArgument
			}
			switch typ {
			case fraPriority:
				ra.priority = &n
			case fraTable:
				ra.table = n
			case fraFwmark:
				ra.mark = &n
			case fraFwmask:
				ra.markMask = &n
			case fraGoto:
				ra.gotoPrio = &n
			case fraSuppressPrefixlen:
				if int32(n) < 0 {
					return ruleAttrs{}, syserr.ErrInvalidArgument
				}
				sup := int32(n)
				ra.suppress = &sup
			}
		case fraProtocol:
			n, ok := v.Uint8()
			if !ok {
				return ruleAttrs{}, syserr.ErrInvalidArgument
			}
			ra.protocol = &n
		case fraIifname, fraOifname:
			name, ok := ruleName(v)
			if !ok {
				return ruleAttrs{}, syserr.ErrInvalidArgument
			}
			if typ == fraIifname {
				ra.iif = &name
			} else {
				ra.oif = &name
			}
		case fraSrc, fraDst:
			if len(v) != ra.addrBytes {
				return ruleAttrs{}, syserr.ErrInvalidArgument
			}
			a := tcpip.AddrFromSlice(v)
			if typ == fraSrc {
				ra.src = &a
			} else {
				ra.dst = &a
			}
		case fraFlow, fraPad:
		}
	}
	return ra, nil
}

// ruleName returns the interface name of a FRA_IIFNAME or FRA_OIFNAME value.
func ruleName(v []byte) (string, bool) {
	if len(v) == 0 || len(v) > ifNameSize {
		return "", false
	}
	for i, c := range v {
		if c == 0 {
			return string(v[:i]), true
		}
	}
	return "", false
}

// newRule handles RTM_NEWRULE like fib_nl_newrule().
func newRule(ns *netstack.Stack, flags uint16, h fibRuleHdr, attrs map[uint16]nlmsg.BytesView) *syserr.Error {
	ra, err := readRuleAttrs(h, attrs)
	if err != nil {
		return err
	}
	r := stack.PolicyRule{
		Action:            stack.RuleAction(h.action),
		Table:             ra.table,
		Invert:            h.flags&fibRuleInvert != 0,
		SrcLen:            h.srcLen,
		DstLen:            h.dstLen,
		TOS:               h.tos,
		SuppressPrefixLen: -1,
	}
	if ra.priority != nil {
		r.Priority = *ra.priority
	} else {
		r.Priority = ns.Stack.DefaultRulePriority(ra.proto)
	}
	if ra.gotoPrio != nil {
		if r.Action != stack.RuleActionGoto {
			return syserr.ErrInvalidArgument
		}
		r.Goto = *ra.gotoPrio
	}
	if ra.mark != nil {
		r.Mark = *ra.mark
		if r.Mark != 0 {
			// A non-zero mark compares every bit unless a mask says otherwise.
			r.MarkMask = 0xffffffff
		}
	}
	if ra.markMask != nil {
		r.MarkMask = *ra.markMask
	}
	if ra.suppress != nil {
		r.SuppressPrefixLen = *ra.suppress
	}
	if ra.protocol != nil {
		r.Protocol = *ra.protocol
	}
	if ra.iif != nil {
		r.InputName = *ra.iif
	}
	if ra.oif != nil {
		r.OutputName = *ra.oif
	}
	if ra.src != nil {
		r.Src = *ra.src
	}
	if ra.dst != nil {
		r.Dst = *ra.dst
	}
	exists := ruleMatchOf(h, ra)
	return translateRuleError(ns.Stack.AddRule(ra.proto, r, stack.RuleInsert{Excl: flags&linux.NLM_F_EXCL != 0, Exists: &exists}))
}

// deleteRule handles RTM_DELRULE like fib_nl_delrule(). A request that leaves a
// field out matches any value of it.
func deleteRule(ns *netstack.Stack, h fibRuleHdr, attrs map[uint16]nlmsg.BytesView) *syserr.Error {
	ra, err := readRuleAttrs(h, attrs)
	if err != nil {
		return err
	}
	m := ruleMatchOf(h, ra)
	_, delErr := ns.Stack.DeleteRule(ra.proto, m)
	return translateRuleError(delErr)
}

// ruleMatchOf returns the selector of the rules that a request names. It
// serves the delete request and the check for a rule that exists.
func ruleMatchOf(h fibRuleHdr, ra ruleAttrs) stack.RuleMatch {
	m := stack.RuleMatch{
		Action:    stack.RuleAction(h.action),
		Table:     ra.table,
		HasTable:  ra.table != 0,
		InputName: ra.iif,
		OutName:   ra.oif,
		Mark:      ra.mark,
		MarkMask:  ra.markMask,
		Goto:      ra.gotoPrio,
		Protocol:  ra.protocol,
		Suppress:  ra.suppress,
		Src:       ra.src,
		Dst:       ra.dst,
		SrcLen:    h.srcLen,
		DstLen:    h.dstLen,
		TOS:       h.tos,
	}
	if ra.priority != nil {
		m.Priority, m.HasPrio = *ra.priority, true
	}
	return m
}

func translateRuleError(err error) *syserr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, stack.ErrRuleExists):
		return syserr.ErrExists
	case errors.Is(err, stack.ErrRuleNotFound):
		return syserr.ErrNoFileOrDir
	}
	return syserr.ErrInvalidArgument
}

// dumpRules writes the rules of the family, or of both families for
// AF_UNSPEC, in lookup order.
func (p *Protocol) dumpRules(ns *netstack.Stack, family uint8, ms *nlmsg.MessageSet) {
	names := make(map[string]struct{})
	for _, info := range ns.Stack.NICInfo() {
		names[info.Name] = struct{}{}
	}
	for _, fam := range []uint8{linux.AF_INET, linux.AF_INET6} {
		if family != linux.AF_UNSPEC && family != fam {
			continue
		}
		proto, _ := ruleProtocol(fam)
		for _, r := range ns.Stack.Rules(proto) {
			putRule(ms, fam, r, names)
		}
	}
}

// putRule appends one RTM_NEWRULE message, in the layout of fib_nl_fill_rule().
func putRule(ms *nlmsg.MessageSet, family uint8, r stack.PolicyRule, nics map[string]struct{}) {
	m := ms.AddMessage(linux.NetlinkMessageHeader{Type: linux.RTM_NEWRULE, Flags: linux.NLM_F_MULTI})
	h := fibRuleHdr{
		family: family, dstLen: r.DstLen, srcLen: r.SrcLen, tos: r.TOS,
		table: ruleTableByte(r.Table), action: uint8(r.Action),
	}
	if r.Invert {
		h.flags |= fibRuleInvert
	}
	if _, ok := nics[r.InputName]; r.InputName != "" && !ok {
		h.flags |= fibRuleIifDetached
	}
	if _, ok := nics[r.OutputName]; r.OutputName != "" && !ok {
		h.flags |= fibRuleOifDetached
	}
	m.Put(primitive.AsByteSlice(h.bytes()))
	m.PutAttr(fraTable, primitive.AllocateUint32(r.Table))
	if r.SuppressPrefixLen >= 0 {
		m.PutAttr(fraSuppressPrefixlen, primitive.AllocateUint32(uint32(r.SuppressPrefixLen)))
	}
	if r.InputName != "" {
		m.PutAttrString(fraIifname, r.InputName)
	}
	if r.OutputName != "" {
		m.PutAttrString(fraOifname, r.OutputName)
	}
	m.PutAttr(fraPriority, primitive.AllocateUint32(r.Priority))
	if r.Mark != 0 || r.MarkMask != 0 {
		m.PutAttr(fraFwmark, primitive.AllocateUint32(r.Mark))
		m.PutAttr(fraFwmask, primitive.AllocateUint32(r.MarkMask))
	}
	if r.Action == stack.RuleActionGoto {
		m.PutAttr(fraGoto, primitive.AllocateUint32(r.Goto))
	}
	if r.Protocol != 0 {
		m.PutAttr(fraProtocol, primitive.AllocateUint8(r.Protocol))
	}
	if r.SrcLen != 0 {
		m.PutAttr(fraSrc, primitive.AsByteSlice(r.Src.AsSlice()))
	}
	if r.DstLen != 0 {
		m.PutAttr(fraDst, primitive.AsByteSlice(r.Dst.AsSlice()))
	}
}

// getRoute answers an RTM_GETROUTE request without the dump flag. A netstack
// answers like ip_route_input() and ip_route_output() do: the rules, the
// mark, and the interfaces of the request pick the route.
func getRoute(st inet.Stack, routes []inet.Route, msg *nlmsg.Message) (inet.Route, *syserr.Error) {
	ns, ok := st.(*netstack.Stack)
	if !ok {
		family, dst, err := parseForDestination(msg)
		if err != nil {
			return inet.Route{}, err
		}
		return fillRoute(routes, family, dst)
	}
	var rtMsg linux.RouteMessage
	attrs, ok := msg.GetData(&rtMsg)
	if !ok {
		return inet.Route{}, syserr.ErrInvalidArgument
	}
	size := header.IPv4AddressSize
	switch rtMsg.Family {
	case linux.AF_INET:
	case linux.AF_INET6:
		size = header.IPv6AddressSize
	default:
		return inet.Route{}, syserr.ErrNotSupported
	}
	flow := netstack.RouteFlow{Family: rtMsg.Family}
	for !attrs.Empty() {
		hdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			break
		}
		attrs = rest
		view := nlmsg.BytesView(value)
		switch hdr.Type {
		case linux.RTA_DST, linux.RTA_SRC:
			if len(value) < size {
				return inet.Route{}, syserr.ErrInvalidArgument
			}
			if hdr.Type == linux.RTA_DST {
				flow.Dst = value[:size]
			} else {
				flow.Src = value[:size]
			}
		case linux.RTA_OIF, linux.RTA_IIF:
			v, ok := view.Int32()
			if !ok {
				return inet.Route{}, syserr.ErrInvalidArgument
			}
			if hdr.Type == linux.RTA_OIF {
				flow.OutputIfIdx = v
			} else {
				flow.InputIfIdx = v
			}
		case linux.RTA_MARK:
			v, ok := view.Uint32()
			if !ok {
				return inet.Route{}, syserr.ErrInvalidArgument
			}
			flow.Mark = v
		}
	}
	if flow.Dst == nil {
		return inet.Route{}, syserr.ErrInvalidArgument
	}
	route, err := ns.LookupRoute(flow)
	if err != nil {
		return inet.Route{}, err
	}
	route.DstLen = uint8(size * 8)
	route.DstAddr = flow.Dst
	route.Flags |= linux.RTM_F_CLONED
	return route, nil
}
