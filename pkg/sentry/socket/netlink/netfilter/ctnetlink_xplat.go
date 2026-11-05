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

package netfilter

import (
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/nftables"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the subsystem NFNL_SUBSYS_CTNETLINK of NETLINK_NETFILTER,
// which conntrack-tools and the kube-proxy of Kubernetes use to list and delete
// tracked connections. It handles IPCTNL_MSG_CT_GET (dump and single entry) and
// IPCTNL_MSG_CT_DELETE, and it answers a dump of the expectation table with no
// entry. Other messages return the error that Linux returns for a message that
// no subsystem handles.
//
// Ref: net/netfilter/nf_conntrack_netlink.c and net/netfilter/nfnetlink.c.

// Message types of the subsystem CTNETLINK and CTNETLINK_EXP, from
// include/uapi/linux/netfilter/nfnetlink_conntrack.h.
const (
	ipctnlMsgCtNew        = 0
	ipctnlMsgCtGet        = 1
	ipctnlMsgCtDelete     = 2
	ipctnlMsgCtGetCtrZero = 3
	ipctnlMsgExpGet       = 1

	// ctnetlinkNewMsgType is the type of every message that this file sends.
	ctnetlinkNewMsgType = linux.NFNL_SUBSYS_CTNETLINK<<8 | ipctnlMsgCtNew

	// nlaTypeMask removes the NLA_F_NESTED and NLA_F_NET_BYTEORDER flags.
	nlaTypeMask = 0x3fff

	conntrackProtocolICMP  = 1
	conntrackProtocolICMP6 = 58
)

// Attributes of a conntrack message, from nfnetlink_conntrack.h.
const (
	ctaTupleOrig  = 1
	ctaTupleReply = 2
	ctaStatus     = 3
	ctaProtoInfo  = 4
	ctaTimeout    = 7
	ctaMark       = 8
	ctaUse        = 11
	ctaID         = 12
	ctaMarkMask   = 21
)

// Attributes of a tuple, of its address, and of its protocol.
const (
	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum        = 1
	ctaProtoSrcPort    = 2
	ctaProtoDstPort    = 3
	ctaProtoICMPID     = 4
	ctaProtoICMPType   = 5
	ctaProtoICMPCode   = 6
	ctaProtoICMPv6ID   = 7
	ctaProtoICMPv6Type = 8
	ctaProtoICMPv6Code = 9

	ctaProtoInfoTCP      = 1
	ctaProtoInfoTCPState = 1
)

// Address families of the first byte of the message.
const (
	afUnspec = 0
	afInet   = 2
	afInet6  = 10
)

// ICMP types of an echo request and its reply.
const (
	icmpEchoRequest  = 8
	icmpEchoReply    = 0
	icmp6EchoRequest = 128
	icmp6EchoReply   = 129
)

// processXplat handles the messages that the nftables code of the upstream
// protocol does not own. It reports false for a message of the nftables
// subsystems while nftables is on. Any other subsystem that this file does not
// implement fails with EINVAL, as on Linux without that subsystem.
func (p *Protocol) processXplat(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) (*syserr.Error, bool) {
	hdr := msg.Header()
	if netlinkMsgPayloadSize(&hdr) < linux.SizeOfNetfilterGenMsg {
		return nil, true
	}
	switch hdr.NetFilterSubsysID() {
	case linux.NFNL_SUBSYS_CTNETLINK:
		return processConntrack(s, msg, ms), true
	case linux.NFNL_SUBSYS_CTNETLINK_EXP:
		return processExpect(msg, ms), true
	case linux.NFNL_SUBSYS_IPSET:
		return processIPSet(ctx, s, msg, ms), true
	case linux.NFNL_SUBSYS_NFTABLES, linux.NFNL_SUBSYS_NFT_COMPAT:
		if nftables.IsNFTablesEnabled() {
			return nil, false
		}
	}
	log.Debugf("Netfilter netlink: subsystem %d is not supported", hdr.NetFilterSubsysID())
	return syserr.ErrInvalidArgument, true
}

// rejectBatch answers a batch whose subsystem is not on. It reports false when
// the batch goes to the nftables code. Linux answers a batch of an absent
// subsystem with EOPNOTSUPP.
func (p *Protocol) rejectBatch(ctx context.Context, s *netlink.Socket, hdr linux.NetlinkMessageHeader) (*syserr.Error, bool) {
	if hdr.Type != linux.NFNL_MSG_BATCH_BEGIN || nftables.IsNFTablesEnabled() {
		return nil, false
	}
	ms := nlmsg.NewMessageSet(s.GetPortID(), hdr.Seq)
	netlink.DumpErrorMessage(hdr, ms, syserr.ErrNotSupported)
	return s.SendResponse(ctx, ms), true
}

// processExpect answers IPCTNL_MSG_EXP_GET with an empty table. The stack has
// no expectations.
func processExpect(msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	if hdr.NetFilterMsgType() != ipctnlMsgExpGet || hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrInvalidArgument
	}
	ms.Multi = true
	return nil
}

// conntrackTable is the part of the stack that ctnetlink reads and changes.
type conntrackTable interface {
	ConntrackScanner() stack.ConntrackScan
	ConntrackLookup(stack.ConntrackTuple) (stack.ConntrackEntry, bool)
	ConntrackDeleteTuple(stack.ConntrackTuple, func(stack.ConntrackEntry) bool) (stack.ConntrackEntry, bool)
	ConntrackDelete(func(stack.ConntrackEntry) bool) int
}

// dumpStarter is the part of the netlink socket that starts a dump.
type dumpStarter interface {
	StartDump(netlink.Dumper) *syserr.Error
}

// processConntrack handles one message of the subsystem CTNETLINK.
func processConntrack(s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	return serveConntrack(s.Stack().(*netstack.Stack).Stack, s, msg, ms)
}

// serveConntrack answers one message of the subsystem CTNETLINK from the table.
// A request for a dump registers the dump with dumps.
func serveConntrack(table conntrackTable, dumps dumpStarter, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	var gen linux.NetFilterGenMsg
	view, ok := msg.GetData(&gen)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	attrs, ok := parseNlAttrs(view)
	if !ok {
		return syserr.ErrInvalidArgument
	}

	switch hdr.Type & 0xff {
	case ipctnlMsgCtGet, ipctnlMsgCtGetCtrZero:
		if hdr.Flags&linux.NLM_F_DUMP == linux.NLM_F_DUMP {
			return dumpConntrack(dumps, table, gen.Family, attrs)
		}
		return getConntrack(table, attrs, ms)
	case ipctnlMsgCtDelete:
		return deleteConntrack(table, gen.Family, attrs)
	}
	log.Debugf("Netfilter netlink: conntrack message %d is not supported", hdr.Type&0xff)
	return syserr.ErrNotSupported
}

// parseNlAttrs returns the attributes of a netlink payload by type, without
// the NLA_F_* flags.
func parseNlAttrs(b []byte) (map[uint16][]byte, bool) {
	attrs := make(map[uint16][]byte)
	view := nlmsg.AttrsView(b)
	for !view.Empty() {
		hdr, value, rest, ok := view.ParseFirst()
		if !ok {
			return nil, false
		}
		attrs[hdr.Type&nlaTypeMask] = value
		view = rest
	}
	return attrs, true
}

// tupleSpec is a tuple that a message names. A field that the message does not
// name matches every value. Linux requires a full tuple. A partial tuple is how
// this implementation serves "conntrack -D" with a filter.
type tupleSpec struct {
	netProto               tcpip.NetworkProtocolNumber
	src, dst               tcpip.Address
	hasSrc, hasDst         bool
	protocol               uint8
	hasProtocol            bool
	srcPort, dstPort       uint16
	hasSrcPort, hasDstPort bool
}

// full reports whether the spec names the whole tuple.
func (t *tupleSpec) full() bool {
	return t.hasSrc && t.hasDst && t.hasProtocol && t.hasSrcPort && t.hasDstPort
}

// matches reports whether the tuple of a connection fits the spec.
func (t *tupleSpec) matches(c stack.ConntrackTuple) bool {
	switch {
	case t.netProto != 0 && t.netProto != c.NetProto,
		t.hasProtocol && tcpip.TransportProtocolNumber(t.protocol) != c.TransProto,
		t.hasSrc && t.src != c.Src,
		t.hasDst && t.dst != c.Dst,
		t.hasSrcPort && t.srcPort != c.SrcPort,
		t.hasDstPort && t.dstPort != c.DstPort:
		return false
	}
	return true
}

// parseTuple parses CTA_TUPLE_ORIG or CTA_TUPLE_REPLY. reply selects the field
// of an ICMP echo identifier: the source field in the original tuple and the
// destination field in the reply tuple.
func parseTuple(value []byte, reply bool) (tupleSpec, *syserr.Error) {
	var t tupleSpec
	outer, ok := parseNlAttrs(value)
	if !ok {
		return t, syserr.ErrInvalidArgument
	}
	if ipAttrs, ok := outer[ctaTupleIP]; ok {
		attrs, ok := parseNlAttrs(ipAttrs)
		if !ok {
			return t, syserr.ErrInvalidArgument
		}
		for typ, v := range attrs {
			switch typ {
			case ctaIPv4Src, ctaIPv4Dst:
				if len(v) != header.IPv4AddressSize {
					return t, syserr.ErrInvalidArgument
				}
				t.netProto = header.IPv4ProtocolNumber
				if typ == ctaIPv4Src {
					t.src, t.hasSrc = tcpip.AddrFromSlice(v), true
				} else {
					t.dst, t.hasDst = tcpip.AddrFromSlice(v), true
				}
			case ctaIPv6Src, ctaIPv6Dst:
				if len(v) != header.IPv6AddressSize {
					return t, syserr.ErrInvalidArgument
				}
				t.netProto = header.IPv6ProtocolNumber
				if typ == ctaIPv6Src {
					t.src, t.hasSrc = tcpip.AddrFromSlice(v), true
				} else {
					t.dst, t.hasDst = tcpip.AddrFromSlice(v), true
				}
			}
		}
	}
	if protoAttrs, ok := outer[ctaTupleProto]; ok {
		attrs, ok := parseNlAttrs(protoAttrs)
		if !ok {
			return t, syserr.ErrInvalidArgument
		}
		if v, ok := attrs[ctaProtoNum]; ok && len(v) >= 1 {
			t.protocol, t.hasProtocol = v[0], true
		}
		port := func(typ uint16) (uint16, bool) {
			v, ok := attrs[typ]
			if !ok || len(v) < 2 {
				return 0, false
			}
			return uint16(v[0])<<8 | uint16(v[1]), true
		}
		switch t.protocol {
		case conntrackProtocolICMP, conntrackProtocolICMP6:
			typ := uint16(ctaProtoICMPID)
			if t.protocol == conntrackProtocolICMP6 {
				typ = ctaProtoICMPv6ID
			}
			if id, ok := port(typ); ok {
				if reply {
					t.dstPort, t.hasDstPort = id, true
					t.srcPort, t.hasSrcPort = 0, true
				} else {
					t.srcPort, t.hasSrcPort = id, true
					t.dstPort, t.hasDstPort = 0, true
				}
			}
		default:
			t.srcPort, t.hasSrcPort = port(ctaProtoSrcPort)
			t.dstPort, t.hasDstPort = port(ctaProtoDstPort)
		}
	}
	return t, nil
}

// connFilter holds what a message selects.
type connFilter struct {
	family   uint8
	orig     *tupleSpec
	reply    *tupleSpec
	hasID    bool
	id       uint32
	hasMark  bool
	mark     uint32
	markMask uint32
}

func readU32(v []byte) (uint32, bool) {
	if len(v) < 4 {
		return 0, false
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3]), true
}

// parseFilter reads the selection of a message from its attributes.
func parseFilter(family uint8, attrs map[uint16][]byte) (*connFilter, *syserr.Error) {
	f := &connFilter{family: family, markMask: 0xffffffff}
	if v, ok := attrs[ctaTupleOrig]; ok {
		t, err := parseTuple(v, false)
		if err != nil {
			return nil, err
		}
		f.orig = &t
	}
	if v, ok := attrs[ctaTupleReply]; ok {
		t, err := parseTuple(v, true)
		if err != nil {
			return nil, err
		}
		f.reply = &t
	}
	if v, ok := attrs[ctaID]; ok {
		id, ok := readU32(v)
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		f.id, f.hasID = id, true
	}
	if v, ok := attrs[ctaMark]; ok {
		mark, ok := readU32(v)
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		f.mark, f.hasMark = mark, true
	}
	if v, ok := attrs[ctaMarkMask]; ok {
		mask, ok := readU32(v)
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		f.markMask = mask
	}
	return f, nil
}

// selectsFamily reports whether an entry of the protocol passes the family of
// the message. AF_UNSPEC passes every family.
func (f *connFilter) selectsFamily(proto tcpip.NetworkProtocolNumber) bool {
	switch f.family {
	case afInet:
		return proto == header.IPv4ProtocolNumber
	case afInet6:
		return proto == header.IPv6ProtocolNumber
	}
	return true
}

// matches reports whether the entry passes every criterion of the filter. The
// stack keeps no connection mark, so an entry has the mark 0.
func (f *connFilter) matches(e stack.ConntrackEntry) bool {
	if !f.selectsFamily(e.Original.NetProto) {
		return false
	}
	if f.orig != nil && !f.orig.matches(e.Original) {
		return false
	}
	if f.reply != nil && !f.reply.matches(e.Reply) {
		return false
	}
	if f.hasMark && f.mark&f.markMask != 0&f.markMask {
		return false
	}
	return !f.hasID || f.id == e.ID
}

// fullTuple returns the tuple that the filter names in full. It fails with
// EINVAL when the original tuple of the filter, or the reply tuple when the
// filter has no original tuple, does not name every field.
func (f *connFilter) fullTuple() (stack.ConntrackTuple, *syserr.Error) {
	spec := f.orig
	if spec == nil {
		spec = f.reply
	}
	if spec == nil || !spec.full() {
		return stack.ConntrackTuple{}, syserr.ErrInvalidArgument
	}
	return stack.ConntrackTuple{
		NetProto:   spec.netProto,
		TransProto: tcpip.TransportProtocolNumber(spec.protocol),
		Src:        spec.src,
		Dst:        spec.dst,
		SrcPort:    spec.srcPort,
		DstPort:    spec.dstPort,
	}, nil
}

// acceptsID reports whether an entry has the ID that the filter names. A
// filter with no ID accepts every entry.
func (f *connFilter) acceptsID(e stack.ConntrackEntry) bool {
	return !f.hasID || f.id == e.ID
}

// findEntry returns the one entry that a full tuple names.
func findEntry(table conntrackTable, f *connFilter) (stack.ConntrackEntry, *syserr.Error) {
	tuple, err := f.fullTuple()
	if err != nil {
		return stack.ConntrackEntry{}, err
	}
	e, ok := table.ConntrackLookup(tuple)
	if !ok || !f.acceptsID(e) {
		return stack.ConntrackEntry{}, syserr.ErrNoFileOrDir
	}
	return e, nil
}

// getConntrack answers IPCTNL_MSG_CT_GET for one tuple.
func getConntrack(table conntrackTable, attrs map[uint16][]byte, ms *nlmsg.MessageSet) *syserr.Error {
	f, err := parseFilter(afUnspec, attrs)
	if err != nil {
		return err
	}
	e, err := findEntry(table, f)
	if err != nil {
		return err
	}
	putEntry(ms.AddMessage(linux.NetlinkMessageHeader{Type: ctnetlinkNewMsgType}), e)
	return nil
}

// deleteConntrack answers IPCTNL_MSG_CT_DELETE. A full tuple deletes one
// connection and fails with ENOENT when it does not exist. A partial tuple, or
// none, deletes every connection that passes the filter.
func deleteConntrack(table conntrackTable, family uint8, attrs map[uint16][]byte) *syserr.Error {
	f, err := parseFilter(family, attrs)
	if err != nil {
		return err
	}
	for _, spec := range []*tupleSpec{f.orig, f.reply} {
		if spec != nil && spec.full() {
			tuple, err := f.fullTuple()
			if err != nil {
				return err
			}
			if _, ok := table.ConntrackDeleteTuple(tuple, f.acceptsID); !ok {
				return syserr.ErrNoFileOrDir
			}
			return nil
		}
	}
	table.ConntrackDelete(f.matches)
	return nil
}

// dumpConntrack answers IPCTNL_MSG_CT_GET with NLM_F_DUMP. It registers a
// dump that the socket resumes with each read, so the answer has no size limit.
func dumpConntrack(dumps dumpStarter, table conntrackTable, family uint8, attrs map[uint16][]byte) *syserr.Error {
	f, err := parseFilter(family, attrs)
	if err != nil {
		return err
	}
	return dumps.StartDump(&conntrackDump{scan: table.ConntrackScanner(), filter: f})
}

// conntrackDump is the state of a dump of the connection table. It scans the
// table one bucket at a time. A connection stays in the bucket of its original
// tuple, so a connection that exists for the whole dump always appears, and
// a connection that a bucket scan sees once never appears again.
type conntrackDump struct {
	scan   stack.ConntrackScan
	filter *connFilter
	// scanned holds the connections of the buckets that the dump scanned and
	// passed the filter. next is the first of them that the dump has not sent.
	scanned []stack.ConntrackEntry
	next    int
	// scratch is the buffer of one bucket scan.
	scratch []stack.ConntrackEntry
	// scanDone is true after the scan of the last bucket.
	scanDone bool
}

var _ netlink.Dumper = (*conntrackDump)(nil)

// DumpChunk implements netlink.Dumper.DumpChunk.
func (d *conntrackDump) DumpChunk(_ context.Context, chunk *nlmsg.MessageSet, limit int) (bool, *syserr.Error) {
	size := 0
	for {
		for d.next < len(d.scanned) {
			m := chunk.AddMessage(linux.NetlinkMessageHeader{Type: ctnetlinkNewMsgType})
			putEntry(m, d.scanned[d.next])
			size += netlink.MessageSize(m)
			if size > limit && len(chunk.Messages) > 1 {
				chunk.Messages = chunk.Messages[:len(chunk.Messages)-1]
				return true, nil
			}
			d.next++
			if size >= limit {
				return true, nil
			}
		}
		if d.scanDone {
			return false, nil
		}
		d.scanBucket()
	}
}

// scanBucket replaces the connections that the dump sent with the connections
// of the next bucket that pass the filter.
func (d *conntrackDump) scanBucket() {
	var more bool
	d.scratch, more = d.scan(d.scratch[:0])
	d.scanDone = !more
	d.scanned, d.next = d.scanned[:0], 0
	for _, e := range d.scratch {
		if d.filter.matches(e) {
			d.scanned = append(d.scanned, e)
		}
	}
}

// DumpDone implements netlink.Dumper.DumpDone.
func (d *conntrackDump) DumpDone() {
	d.scanned, d.scratch = nil, nil
}

// putEntry appends the attributes of a connection to m, in the order that
// Linux uses.
func putEntry(m *nlmsg.Message, e stack.ConntrackEntry) {
	m.Put(&linux.NetFilterGenMsg{Family: familyOf(e.Original.NetProto), Version: linux.NFNETLINK_V0})
	m.PutNestedAttr(ctaTupleOrig|linux.NLA_F_NESTED, tupleAttrs(e.Original, false))
	m.PutNestedAttr(ctaTupleReply|linux.NLA_F_NESTED, tupleAttrs(e.Reply, true))
	m.PutAttr(ctaStatus, nlmsg.PutU32(e.Status))
	m.PutAttr(ctaTimeout, nlmsg.PutU32(uint32(e.Timeout/time.Second)))
	if e.HasTCPState {
		var tcp nlmsg.NestedAttr
		tcp.PutAttr(ctaProtoInfoTCPState, nlmsg.PutU8(e.TCPState))
		var info nlmsg.NestedAttr
		info.PutAttr(ctaProtoInfoTCP|linux.NLA_F_NESTED, primitive.AsByteSlice(tcp))
		m.PutNestedAttr(ctaProtoInfo|linux.NLA_F_NESTED, info)
	}
	m.PutAttr(ctaMark, nlmsg.PutU32(0))
	m.PutAttr(ctaID, nlmsg.PutU32(e.ID))
	m.PutAttr(ctaUse, nlmsg.PutU32(1))
}

func familyOf(proto tcpip.NetworkProtocolNumber) uint8 {
	if proto == header.IPv6ProtocolNumber {
		return afInet6
	}
	return afInet
}

// tupleAttrs returns the attributes of CTA_TUPLE_ORIG or CTA_TUPLE_REPLY: the
// addresses, then the protocol with its ports or its ICMP echo identity.
func tupleAttrs(t stack.ConntrackTuple, reply bool) nlmsg.NestedAttr {
	var ip nlmsg.NestedAttr
	srcType, dstType := uint16(ctaIPv4Src), uint16(ctaIPv4Dst)
	if t.NetProto == header.IPv6ProtocolNumber {
		srcType, dstType = ctaIPv6Src, ctaIPv6Dst
	}
	ip.PutAttr(srcType, primitive.AsByteSlice(t.Src.AsSlice()))
	ip.PutAttr(dstType, primitive.AsByteSlice(t.Dst.AsSlice()))

	var proto nlmsg.NestedAttr
	proto.PutAttr(ctaProtoNum, nlmsg.PutU8(uint8(t.TransProto)))
	switch t.TransProto {
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		id, typ := t.SrcPort, uint8(icmpEchoRequest)
		idType, typeType, codeType := uint16(ctaProtoICMPID), uint16(ctaProtoICMPType), uint16(ctaProtoICMPCode)
		if t.TransProto == header.ICMPv6ProtocolNumber {
			typ = icmp6EchoRequest
			idType, typeType, codeType = ctaProtoICMPv6ID, ctaProtoICMPv6Type, ctaProtoICMPv6Code
		}
		if reply {
			id = t.DstPort
			typ = icmpEchoReply
			if t.TransProto == header.ICMPv6ProtocolNumber {
				typ = icmp6EchoReply
			}
		}
		proto.PutAttr(idType, nlmsg.PutU16(id))
		proto.PutAttr(typeType, nlmsg.PutU8(typ))
		proto.PutAttr(codeType, nlmsg.PutU8(0))
	default:
		proto.PutAttr(ctaProtoSrcPort, nlmsg.PutU16(t.SrcPort))
		proto.PutAttr(ctaProtoDstPort, nlmsg.PutU16(t.DstPort))
	}

	var out nlmsg.NestedAttr
	out.PutAttr(ctaTupleIP|linux.NLA_F_NESTED, primitive.AsByteSlice(ip))
	out.PutAttr(ctaTupleProto|linux.NLA_F_NESTED, primitive.AsByteSlice(proto))
	return out
}
