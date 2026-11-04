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
	"slices"

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
	"z.gfire.dev/gvx/pkg/tcpip/link/vxlan"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Neighbor attributes and constants of include/uapi/linux/neighbour.h.
const (
	ndaDst       = 1
	ndaLLAddr    = 2
	ndaPort      = 6
	ndaVNI       = 7
	ndaIfindex   = 8
	ndaMaster    = 9
	ndmsgSize    = 12
	ifinfoSize   = 16
	iflaMaster   = 10
	afBridge     = 7
	rtnUnicast   = 1
	nudIncomp    = 0x01
	nudReachable = 0x02
	nudStale     = 0x04
	nudDelay     = 0x08
	nudProbe     = 0x10
	nudFailed    = 0x20
	nudNoARP     = 0x40
	nudPermanent = 0x80
	ntfSelf      = 0x02
	ntfMaster    = 0x04
	// ntfFDBKept are the flags that an FDB entry keeps from its request.
	ntfFDBKept = 0x10 | 0x80 // NTF_EXT_LEARNED | NTF_ROUTER
)

// ndmsg is struct ndmsg, the header of a neighbor message.
type ndmsg struct {
	family  uint8
	ifindex int32
	state   uint16
	flags   uint8
	typ     uint8
}

func (n ndmsg) bytes() []byte {
	b := make([]byte, ndmsgSize)
	b[0] = n.family
	binary.NativeEndian.PutUint32(b[4:], uint32(n.ifindex))
	binary.NativeEndian.PutUint16(b[8:], n.state)
	b[10], b[11] = n.flags, n.typ
	return b
}

// isNeighMessage reports whether the message type belongs to the neighbor
// table or the FDB.
func isNeighMessage(typ uint16) bool {
	return typ == linux.RTM_NEWNEIGH || typ == linux.RTM_DELNEIGH || typ == linux.RTM_GETNEIGH
}

// parseNdmsg returns the header and the attributes of a neighbor message.
//
// A dump request of the family AF_BRIDGE can also carry struct ifinfomsg, which
// is longer than struct ndmsg. iproute2 sends that form for "bridge fdb show".
// The two forms share the position of the family and the interface index, so
// the check of fdb_valid_dump_legacy in Linux tells them apart by the length:
// struct ndmsg, alone or with one IFLA_MASTER attribute, is the short form.
func parseNdmsg(msg *nlmsg.Message) (ndmsg, map[uint16]nlmsg.BytesView, bool) {
	buf := msg.Buffer()
	if len(buf) < linux.NetlinkMessageHeaderSize+ndmsgSize {
		return ndmsg{}, nil, false
	}
	b := buf[linux.NetlinkMessageHeaderSize:]
	nd := ndmsg{
		family:  b[0],
		ifindex: int32(binary.NativeEndian.Uint32(b[4:])),
		state:   binary.NativeEndian.Uint16(b[8:]),
		flags:   b[10],
		typ:     b[11],
	}
	bodyEnd := ndmsgSize
	if msg.Header().Type == linux.RTM_GETNEIGH && nd.family == afBridge && !isShortFDBDump(b) {
		if len(b) < ifinfoSize {
			return nd, nil, false
		}
		nd.state, nd.flags, nd.typ = 0, 0, 0
		bodyEnd = ifinfoSize
	}
	attrs, ok := nlmsg.AttrsView(b[bodyEnd:]).Parse()
	if v, master := attrs[iflaMaster]; master {
		// Both forms name the bridge in IFLA_MASTER. A request of the type
		// struct ndmsg names it in NDA_MASTER, which dumpNeigh reads.
		attrs[ndaMaster] = v
	}
	return nd, attrs, ok
}

// isShortFDBDump reports whether the body of a dump request of the family
// AF_BRIDGE is struct ndmsg, with or without one IFLA_MASTER attribute.
func isShortFDBDump(body []byte) bool {
	switch len(body) {
	case ndmsgSize:
		return true
	case ndmsgSize + 8:
		return binary.NativeEndian.Uint16(body[ndmsgSize+2:]) == iflaMaster
	}
	return false
}

// processNeigh answers RTM_NEWNEIGH, RTM_DELNEIGH, and RTM_GETNEIGH. The
// family AF_INET or AF_INET6 selects the neighbor table of a link, and the
// family AF_BRIDGE selects the forwarding table of a vxlan link.
func (p *Protocol) processNeigh(_ context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	st, ok := s.Stack().(*netstack.Stack)
	if !ok {
		return syserr.ErrProtocolNotSupported
	}
	hdr := msg.Header()
	if hdr.Flags&linux.NLM_F_REQUEST == 0 {
		return syserr.ErrNotSupported
	}
	nd, attrs, ok := parseNdmsg(msg)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	switch hdr.Type {
	case linux.RTM_GETNEIGH:
		if hdr.Flags&(linux.NLM_F_DUMP|linux.NLM_F_ROOT) != 0 {
			return dumpNeigh(st, nd, attrs, ms)
		}
		return getNeigh(st, nd, attrs, ms)
	case linux.RTM_NEWNEIGH:
		if nd.family == afBridge {
			return newFDB(st, nd, attrs, hdr.Flags)
		}
		return newNeigh(st, nd, attrs, hdr.Flags)
	default:
		if nd.family == afBridge {
			return delFDB(st, nd, attrs)
		}
		return delNeigh(st, nd, attrs)
	}
}

// neighProto returns the network protocol of the family of a neighbor message.
func neighProto(family uint8) (tcpip.NetworkProtocolNumber, int, bool) {
	switch family {
	case linux.AF_INET:
		return ipv4.ProtocolNumber, header.IPv4AddressSize, true
	case linux.AF_INET6:
		return ipv6.ProtocolNumber, header.IPv6AddressSize, true
	}
	return 0, 0, false
}

// neighKey is the link and the destination address of a request.
type neighKey struct {
	nic   tcpip.NICID
	proto tcpip.NetworkProtocolNumber
	addr  tcpip.Address
}

// parseNeighKey reads the link and NDA_DST of an IPv4 or IPv6 request.
func parseNeighKey(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView) (neighKey, *syserr.Error) {
	proto, size, ok := neighProto(nd.family)
	if !ok {
		return neighKey{}, syserr.ErrNotSupported
	}
	dst, ok := attrs[ndaDst]
	if !ok || len(dst) != size {
		return neighKey{}, syserr.ErrInvalidArgument
	}
	if nd.ifindex <= 0 {
		return neighKey{}, syserr.ErrInvalidArgument
	}
	if _, ok := st.Stack.SingleNICInfo(tcpip.NICID(nd.ifindex)); !ok {
		return neighKey{}, syserr.ErrNoDevice
	}
	return neighKey{nic: tcpip.NICID(nd.ifindex), proto: proto, addr: tcpip.AddrFromSlice(dst)}, nil
}

// nudOf returns the NUD_* state of a neighbor cache entry.
func nudOf(s stack.NeighborState) uint16 {
	switch s {
	case stack.Incomplete:
		return nudIncomp
	case stack.Reachable:
		return nudReachable
	case stack.Stale:
		return nudStale
	case stack.Delay:
		return nudDelay
	case stack.Probe:
		return nudProbe
	case stack.Static:
		return nudPermanent
	case stack.Unreachable:
		return nudFailed
	}
	return 0
}

// maxStaticNeighbors is the largest count of static entries in the neighbor
// table of one link and one IP family. The table of the stack does not bound
// them, and a guest could fill the memory of the sandbox otherwise. Linux
// answers a full table with ENOBUFS.
const maxStaticNeighbors = 65536

// findNeigh returns the entry of the key, if the table of the link has one.
func findNeigh(st *netstack.Stack, k neighKey) (stack.NeighborEntry, bool, *syserr.Error) {
	e, ok, err := st.Stack.NeighborLookup(k.nic, k.proto, k.addr)
	if err != nil {
		return stack.NeighborEntry{}, false, syserr.TranslateNetstackError(err)
	}
	return e, ok, nil
}

// putNeigh appends one RTM_NEWNEIGH message for an entry of the neighbor table.
func putNeigh(ms *nlmsg.MessageSet, family uint8, nic tcpip.NICID, e stack.NeighborEntry) {
	m := ms.AddMessage(linux.NetlinkMessageHeader{Type: linux.RTM_NEWNEIGH})
	m.Put(primitive.AsByteSlice(ndmsg{family: family, ifindex: int32(nic), state: nudOf(e.State), typ: rtnUnicast}.bytes()))
	m.PutAttr(ndaDst, primitive.AsByteSlice(e.Addr.AsSlice()))
	if len(e.LinkAddr) != 0 {
		m.PutAttr(ndaLLAddr, primitive.AsByteSlice([]byte(e.LinkAddr)))
	}
}

// newNeigh adds or changes an entry of the neighbor table. A static entry
// (state NUD_PERMANENT or NUD_NOARP) needs the Ethernet address. A dynamic
// state is not supported, because the table has no way to set it.
func newNeigh(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView, flags uint16) *syserr.Error {
	k, err := parseNeighKey(st, nd, attrs)
	if err != nil {
		return err
	}
	if nd.state&(nudPermanent|nudNoARP) == 0 {
		return syserr.ErrNotSupported
	}
	mac, ok := attrs[ndaLLAddr]
	if !ok || len(mac) != tcpip.LinkAddressSize {
		return syserr.ErrInvalidArgument
	}
	_, exists, err := findNeigh(st, k)
	if err != nil {
		return err
	}
	switch {
	case exists && flags&linux.NLM_F_EXCL != 0:
		return syserr.ErrExists
	case exists && flags&linux.NLM_F_REPLACE == 0:
		return nil
	case !exists && flags&linux.NLM_F_CREATE == 0:
		return syserr.ErrNoFileOrDir
	}
	if !exists {
		n, terr := st.Stack.StaticNeighborCount(k.nic, k.proto)
		if terr != nil {
			return syserr.TranslateNetstackError(terr)
		}
		if n >= maxStaticNeighbors {
			return syserr.ErrNoBufferSpace
		}
	}
	return syserr.TranslateNetstackError(st.Stack.AddStaticNeighbor(k.nic, k.proto, k.addr, tcpip.LinkAddress(mac)))
}

// delNeigh removes an entry of the neighbor table.
func delNeigh(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView) *syserr.Error {
	k, err := parseNeighKey(st, nd, attrs)
	if err != nil {
		return err
	}
	switch terr := st.Stack.RemoveNeighbor(k.nic, k.proto, k.addr).(type) {
	case nil:
		return nil
	case *tcpip.ErrBadAddress:
		return syserr.ErrNoFileOrDir
	default:
		return syserr.TranslateNetstackError(terr)
	}
}

// getNeigh answers a request for one entry of the neighbor table.
func getNeigh(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView, ms *nlmsg.MessageSet) *syserr.Error {
	k, err := parseNeighKey(st, nd, attrs)
	if err != nil {
		return err
	}
	e, ok, err := findNeigh(st, k)
	if err != nil {
		return err
	}
	if !ok {
		return syserr.ErrNoFileOrDir
	}
	putNeigh(ms, nd.family, k.nic, e)
	return nil
}

// dumpNeigh lists the neighbor entries of the links, or the FDB entries of the
// vxlan links for the family AF_BRIDGE. A request with an interface index lists
// only that link. A family without a table lists nothing.
func dumpNeigh(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView, ms *nlmsg.MessageSet) *syserr.Error {
	ms.Multi = true
	only := tcpip.NICID(nd.ifindex)
	if v, ok := attrs[ndaIfindex]; ok {
		if idx, ok := v.Uint32(); ok {
			only = tcpip.NICID(idx)
		}
	}
	var master tcpip.NICID
	if v, ok := attrs[ndaMaster]; ok {
		if idx, ok := v.Uint32(); ok {
			master = tcpip.NICID(idx)
		}
	}
	nics := st.Stack.NICInfo()
	ids := make([]tcpip.NICID, 0, len(nics))
	for id := range nics {
		if only != 0 && only != id {
			continue
		}
		if coordinator, _ := st.Stack.GetNICCoordinatorID(id); master != 0 && coordinator != master {
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if nd.family == afBridge {
			if ep := st.VxlanLink(id); ep != nil {
				putFDB(ms, id, ep)
			}
			continue
		}
		for _, family := range []uint8{linux.AF_INET, linux.AF_INET6} {
			if nd.family != linux.AF_UNSPEC && nd.family != family {
				continue
			}
			proto, _, _ := neighProto(family)
			entries, err := st.Stack.Neighbors(id, proto)
			if err != nil {
				// The link has no table for the protocol, as the loopback has none.
				continue
			}
			slices.SortFunc(entries, func(a, b stack.NeighborEntry) int { return slices.Compare(a.Addr.AsSlice(), b.Addr.AsSlice()) })
			for _, e := range entries {
				putNeigh(ms, family, id, e)
			}
		}
	}
	return nil
}

// fdbRequest is a parsed FDB request.
type fdbRequest struct {
	ep     *vxlan.Endpoint
	mac    tcpip.LinkAddress
	remote vxlan.Remote
	state  uint16
	flags  uint8
}

// parseFDB reads an FDB request for a vxlan link. A request for another kind of
// link fails with EOPNOTSUPP, and an unknown link with ENODEV. A request for the
// master of the link, without NTF_SELF, fails with EOPNOTSUPP, because a vxlan
// link has no master table in the Sentry.
func parseFDB(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView) (fdbRequest, *syserr.Error) {
	var r fdbRequest
	if nd.ifindex <= 0 {
		return r, syserr.ErrInvalidArgument
	}
	id := tcpip.NICID(nd.ifindex)
	if _, ok := st.Stack.SingleNICInfo(id); !ok {
		return r, syserr.ErrNoDevice
	}
	if nd.flags&ntfMaster != 0 && nd.flags&ntfSelf == 0 {
		return r, syserr.ErrNotSupported
	}
	if r.ep = st.VxlanLink(id); r.ep == nil {
		return r, syserr.ErrNotSupported
	}
	mac, ok := attrs[ndaLLAddr]
	if !ok || len(mac) != tcpip.LinkAddressSize {
		return r, syserr.ErrInvalidArgument
	}
	r.mac = tcpip.LinkAddress(mac)
	cfg := r.ep.Config()
	r.remote = vxlan.Remote{Port: cfg.Port, VNI: cfg.VNI}
	if v, ok := attrs[ndaDst]; ok {
		if len(v) != header.IPv4AddressSize && len(v) != header.IPv6AddressSize {
			// vxlan_nla_get_addr answers EAFNOSUPPORT for a short address.
			return r, syserr.ErrAddressFamilyNotSupported
		}
		r.remote.IP = tcpip.AddrFromSlice(v)
	}
	if v, ok := attrs[ndaPort]; ok {
		if len(v) != 2 {
			return r, syserr.ErrInvalidArgument
		}
		r.remote.Port = binary.BigEndian.Uint16(v)
	}
	if v, ok := attrs[ndaVNI]; ok {
		vni, ok := v.Uint32()
		if !ok {
			return r, syserr.ErrInvalidArgument
		}
		if vni > vxlan.MaxVNI {
			return r, syserr.ErrRange
		}
		r.remote.VNI = vni
	}
	if v, ok := attrs[ndaIfindex]; ok {
		idx, ok := v.Uint32()
		if !ok {
			return r, syserr.ErrInvalidArgument
		}
		if idx != 0 {
			if _, ok := st.Stack.SingleNICInfo(tcpip.NICID(idx)); !ok {
				return r, syserr.ErrAddressNotAvailable
			}
		}
		r.remote.Link = tcpip.NICID(idx)
	}
	r.state = nd.state
	r.flags = nd.flags&ntfFDBKept | ntfSelf
	return r, nil
}

// newFDB adds or changes an FDB entry of a vxlan link, as vxlan_fdb_add does.
func newFDB(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView, flags uint16) *syserr.Error {
	r, err := parseFDB(st, nd, attrs)
	if err != nil {
		return err
	}
	mode := vxlan.UpdateMode{
		Create:  flags&linux.NLM_F_CREATE != 0,
		Excl:    flags&linux.NLM_F_EXCL != 0,
		Replace: flags&linux.NLM_F_REPLACE != 0,
		Append:  flags&linux.NLM_F_APPEND != 0,
	}
	if verr := r.ep.FDBUpdate(r.mac, r.state, r.flags, r.remote, mode); verr != nil {
		return netstack.VxlanSyserr(verr)
	}
	return nil
}

// delFDB removes an FDB entry of a vxlan link, or one remote of the entry.
func delFDB(st *netstack.Stack, nd ndmsg, attrs map[uint16]nlmsg.BytesView) *syserr.Error {
	r, err := parseFDB(st, nd, attrs)
	if err != nil {
		return err
	}
	if verr := r.ep.FDBDelete(r.mac, r.remote); verr != nil {
		return netstack.VxlanSyserr(verr)
	}
	return nil
}

// putFDB appends one RTM_NEWNEIGH message of the family AF_BRIDGE for each
// remote of each entry of the link. An entry with no remote gets one message.
func putFDB(ms *nlmsg.MessageSet, id tcpip.NICID, ep *vxlan.Endpoint) {
	cfg := ep.Config()
	for _, e := range ep.FDB() {
		remotes := e.Remotes
		if len(remotes) == 0 {
			remotes = []vxlan.Remote{{}}
		}
		for _, r := range remotes {
			m := ms.AddMessage(linux.NetlinkMessageHeader{Type: linux.RTM_NEWNEIGH})
			m.Put(primitive.AsByteSlice(ndmsg{family: afBridge, ifindex: int32(id), state: e.State, flags: e.Flags | ntfSelf, typ: rtnUnicast}.bytes()))
			m.PutAttr(ndaLLAddr, primitive.AsByteSlice([]byte(e.MAC)))
			if r.IP.Len() != 0 && !r.IP.Unspecified() {
				m.PutAttr(ndaDst, primitive.AsByteSlice(r.IP.AsSlice()))
			}
			if r.IP.Len() != 0 && r.Port != cfg.Port {
				m.PutAttr(ndaPort, primitive.AsByteSlice(binary.BigEndian.AppendUint16(nil, r.Port)))
			}
			if r.IP.Len() != 0 && r.VNI != cfg.VNI {
				m.PutAttr(ndaVNI, primitive.AllocateUint32(r.VNI))
			}
			if r.Link != 0 {
				m.PutAttr(ndaIfindex, primitive.AllocateUint32(uint32(r.Link)))
			}
		}
	}
}

// putLinkInfoData appends IFLA_INFO_DATA for the links whose kind has one. The
// notification messages have no stack, so they carry the kind only.
func putLinkInfoData(info *nlmsg.NestedAttr, st inet.Stack, idx int32, i inet.Interface) {
	if i.Kind != "vxlan" {
		return
	}
	if ns, ok := st.(*netstack.Stack); ok {
		ns.VxlanInfoData(tcpip.NICID(idx), info)
	}
}
