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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the xt_addrtype match (iptables "-m addrtype").
// Ref: include/uapi/linux/netfilter/xt_addrtype.h and net/netfilter/xt_addrtype.c.
// Docker adds "-m addrtype --dst-type LOCAL" to the nat PREROUTING, OUTPUT and
// POSTROUTING chains.

const (
	matcherNameAddrtype = "addrtype"

	// addrtypeRevision0 is struct xt_addrtype_info (IPv4 only).
	addrtypeRevision0 uint8 = 0
	// addrtypeRevision1 is struct xt_addrtype_info_v1 (IPv4 and IPv6).
	addrtypeRevision1 uint8 = 1

	// addrtypeIPv6Unsupported lists the types that Linux rejects for IPv6 rules.
	// Linux rejects BLACKHOLE, BROADCAST and every type from PROHIBIT upward.
	addrtypeIPv6Unsupported = linux.XT_ADDRTYPE_BLACKHOLE |
		linux.XT_ADDRTYPE_BROADCAST |
		linux.XT_ADDRTYPE_PROHIBIT |
		linux.XT_ADDRTYPE_THROW |
		linux.XT_ADDRTYPE_NAT |
		linux.XT_ADDRTYPE_XRESOLVE
)

func init() {
	registerMatchMaker(addrtypeMarshaler{rev: addrtypeRevision0})
	registerMatchMaker(addrtypeMarshaler{rev: addrtypeRevision1})
}

// addrResolver answers the questions that the classification of an address
// needs. A fake implements it in unit tests.
type addrResolver interface {
	// nicIDByName returns the ID of the named NIC, or 0 if the name is empty or
	// unknown. 0 means "no interface limit".
	nicIDByName(name string) tcpip.NICID
	// nicIsLoopback returns true if the NIC is a loopback NIC.
	nicIsLoopback(id tcpip.NICID) bool
	// addressAssigned returns true if the address is assigned to the NIC. With
	// nicID 0, any NIC counts.
	addressAssigned(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool
	// subnetBroadcast returns true if the address is the broadcast address of
	// a subnet of the NIC. With nicID 0, any NIC counts.
	subnetBroadcast(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool
}

// stackResolver implements addrResolver on a netstack Stack.
type stackResolver struct {
	stk *stack.Stack
}

func (r stackResolver) nicIDByName(name string) tcpip.NICID {
	if name == "" {
		return 0
	}
	return r.stk.NICIDByName(name)
}

func (r stackResolver) nicIsLoopback(id tcpip.NICID) bool {
	return r.stk.NICIsLoopback(id)
}

func (r stackResolver) addressAssigned(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return r.stk.AddressAssignedOnNIC(nicID, proto, addr)
}

func (r stackResolver) subnetBroadcast(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	return r.stk.IsSubnetBroadcast(nicID, proto, addr)
}

// classifyAddress returns the single XT_ADDRTYPE_* bit that describes addr.
// If nicID is not 0, only addresses of that NIC can be LOCAL or BROADCAST.
// Linux has the same rule: a route type only counts when the route uses the
// named device.
func classifyAddress(r addrResolver, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, nicID tcpip.NICID) uint16 {
	switch proto {
	case header.IPv4ProtocolNumber:
		return classifyIPv4(r, addr, nicID)
	case header.IPv6ProtocolNumber:
		return classifyIPv6(r, addr, nicID)
	default:
		return linux.XT_ADDRTYPE_UNSPEC
	}
}

func classifyIPv4(r addrResolver, addr tcpip.Address, nicID tcpip.NICID) uint16 {
	octets := addr.As4()
	switch {
	// 0.0.0.0/8 and 255.255.255.255 count as broadcast in Linux
	// (ipv4_is_zeronet and ipv4_is_lbcast).
	case octets[0] == 0 || addr == header.IPv4Broadcast:
		return linux.XT_ADDRTYPE_BROADCAST
	case header.IsV4MulticastAddress(addr):
		return linux.XT_ADDRTYPE_MULTICAST
	// WHY: the loopback NIC owns 127.0.0.0/8 but holds only 127.0.0.1 as an
	// address. Linux treats the whole range as LOCAL on "lo".
	case header.IsV4LoopbackAddress(addr):
		if nicID == 0 || r.nicIsLoopback(nicID) {
			return linux.XT_ADDRTYPE_LOCAL
		}
		return linux.XT_ADDRTYPE_UNICAST
	// WHY: the stack reports a subnet broadcast address as assigned. Test it
	// before the assigned address, or it would count as LOCAL.
	case r.subnetBroadcast(nicID, header.IPv4ProtocolNumber, addr):
		return linux.XT_ADDRTYPE_BROADCAST
	case r.addressAssigned(nicID, header.IPv4ProtocolNumber, addr):
		return linux.XT_ADDRTYPE_LOCAL
	default:
		return linux.XT_ADDRTYPE_UNICAST
	}
}

func classifyIPv6(r addrResolver, addr tcpip.Address, nicID tcpip.NICID) uint16 {
	switch {
	case addr == header.IPv6Any:
		return linux.XT_ADDRTYPE_UNSPEC
	case header.IsV6MulticastAddress(addr):
		return linux.XT_ADDRTYPE_MULTICAST
	case header.IsV6LoopbackAddress(addr):
		if nicID == 0 || r.nicIsLoopback(nicID) {
			return linux.XT_ADDRTYPE_LOCAL
		}
		return linux.XT_ADDRTYPE_UNICAST
	case r.addressAssigned(nicID, header.IPv6ProtocolNumber, addr):
		return linux.XT_ADDRTYPE_LOCAL
	default:
		return linux.XT_ADDRTYPE_UNICAST
	}
}

// addrtypeMarshaler implements matchMaker for the addrtype match.
type addrtypeMarshaler struct {
	rev uint8
}

// name implements matchMaker.name.
func (addrtypeMarshaler) name() string {
	return matcherNameAddrtype
}

// revision implements matchMaker.revision.
func (m addrtypeMarshaler) revision() uint8 {
	return m.rev
}

// marshal implements matchMaker.marshal.
func (m addrtypeMarshaler) marshal(mr matcher) []byte {
	am := mr.(*AddrtypeMatcher)
	var data []byte
	switch am.rev {
	case addrtypeRevision0:
		info := linux.XTAddrtypeInfo{Source: am.source, Dest: am.dest}
		if am.invertSource {
			info.InvertSource = 1
		}
		if am.invertDest {
			info.InvertDest = 1
		}
		data = make([]byte, info.SizeBytes())
		info.MarshalBytes(data)
	default:
		info := linux.XTAddrtypeInfoV1{Source: am.source, Dest: am.dest}
		if am.invertSource {
			info.Flags |= linux.XT_ADDRTYPE_INVERT_SOURCE
		}
		if am.invertDest {
			info.Flags |= linux.XT_ADDRTYPE_INVERT_DEST
		}
		if am.limitIfaceIn {
			info.Flags |= linux.XT_ADDRTYPE_LIMIT_IFACE_IN
		}
		if am.limitIfaceOut {
			info.Flags |= linux.XT_ADDRTYPE_LIMIT_IFACE_OUT
		}
		data = make([]byte, info.SizeBytes())
		info.MarshalBytes(data)
	}
	buf := marshalEntryMatch(matcherNameAddrtype, data)
	// marshalEntryMatch leaves Revision at 0. Iptables picks the user space
	// parser from this byte, so it must hold the revision of the rule.
	buf[revisionOffset] = am.rev
	return buf
}

// unmarshal implements matchMaker.unmarshal.
func (m addrtypeMarshaler) unmarshal(_ IDMapper, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	ipv6 := filter.NetworkProtocol() == header.IPv6ProtocolNumber
	am := &AddrtypeMatcher{rev: m.rev}
	switch m.rev {
	case addrtypeRevision0:
		var info linux.XTAddrtypeInfo
		if want := bits.AlignUp(info.SizeBytes(), 8); len(buf) != want {
			return nil, fmt.Errorf("addrtype rev0: buf has size %d, want %d", len(buf), want)
		}
		if ipv6 {
			return nil, fmt.Errorf("addrtype rev0: IPv6 is not supported")
		}
		info.UnmarshalBytes(buf[:info.SizeBytes()])
		am.source, am.dest = info.Source, info.Dest
		am.invertSource, am.invertDest = info.InvertSource != 0, info.InvertDest != 0
	case addrtypeRevision1:
		var info linux.XTAddrtypeInfoV1
		// WHY: Linux requires the exact aligned size. The size also tells the
		// revisions apart, because unmarshalMatcherRevs tries the highest
		// revision first and ignores the revision of the rule.
		if want := bits.AlignUp(info.SizeBytes(), 8); len(buf) != want {
			return nil, fmt.Errorf("addrtype rev1: buf has size %d, want %d", len(buf), want)
		}
		info.UnmarshalBytes(buf[:info.SizeBytes()])
		if info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0 && info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0 {
			return nil, fmt.Errorf("addrtype rev1: both interface limits are set")
		}
		if ipv6 && (info.Source|info.Dest)&addrtypeIPv6Unsupported != 0 {
			return nil, fmt.Errorf("addrtype rev1: type mask 0x%x/0x%x is not valid for IPv6", info.Source, info.Dest)
		}
		am.source, am.dest = info.Source, info.Dest
		am.invertSource = info.Flags&linux.XT_ADDRTYPE_INVERT_SOURCE != 0
		am.invertDest = info.Flags&linux.XT_ADDRTYPE_INVERT_DEST != 0
		am.limitIfaceIn = info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_IN != 0
		am.limitIfaceOut = info.Flags&linux.XT_ADDRTYPE_LIMIT_IFACE_OUT != 0
	default:
		return nil, fmt.Errorf("addrtype: unknown revision %d", m.rev)
	}
	nflog("parsed addrtype rev%d: %+v", m.rev, am)
	return am, nil
}

// AddrtypeMatcher matches the type (LOCAL, UNICAST, ...) of the source and
// destination address of a packet.
type AddrtypeMatcher struct {
	rev uint8
	// source and dest are bit masks of XT_ADDRTYPE_* values. A zero mask
	// disables the test for that address.
	source        uint16
	dest          uint16
	invertSource  bool
	invertDest    bool
	limitIfaceIn  bool
	limitIfaceOut bool

	// resolver is nil until bindStack runs. A nil resolver classifies every
	// address as UNICAST.
	resolver addrResolver
}

// name implements matcher.name.
func (*AddrtypeMatcher) name() string {
	return matcherNameAddrtype
}

// revision implements matcher.revision.
func (am *AddrtypeMatcher) revision() uint8 {
	return am.rev
}

// bindStack implements stackBinder.bindStack.
func (am *AddrtypeMatcher) bindStack(stk *stack.Stack) {
	am.resolver = stackResolver{stk: stk}
}

// Match implements stack.Matcher.Match.
func (am *AddrtypeMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, inNicName, outNicName string) (bool, bool) {
	src, dst, ok := packetAddresses(pkt)
	if !ok {
		return false, true
	}
	r := am.resolver
	if r == nil {
		r = unboundResolver{}
	}

	var nicID tcpip.NICID
	switch {
	case am.limitIfaceIn:
		nicID = r.nicIDByName(inNicName)
	case am.limitIfaceOut:
		nicID = r.nicIDByName(outNicName)
	}

	proto := pkt.NetworkProtocolNumber
	if am.source != 0 {
		matches := am.source&classifyAddress(r, proto, src, nicID) != 0
		if matches == am.invertSource {
			return false, false
		}
	}
	if am.dest != 0 {
		matches := am.dest&classifyAddress(r, proto, dst, nicID) != 0
		if matches == am.invertDest {
			return false, false
		}
	}
	return true, false
}

// packetAddresses returns the source and destination address of the network
// header of pkt.
func packetAddresses(pkt *stack.PacketBuffer) (src, dst tcpip.Address, ok bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(pkt.NetworkHeader().Slice())
		if len(hdr) < header.IPv4MinimumSize {
			return tcpip.Address{}, tcpip.Address{}, false
		}
		return hdr.SourceAddress(), hdr.DestinationAddress(), true
	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(pkt.NetworkHeader().Slice())
		if len(hdr) < header.IPv6MinimumSize {
			return tcpip.Address{}, tcpip.Address{}, false
		}
		return hdr.SourceAddress(), hdr.DestinationAddress(), true
	default:
		return tcpip.Address{}, tcpip.Address{}, false
	}
}

// unboundResolver is the resolver of a matcher that has no stack. It knows no
// NIC and no assigned address.
type unboundResolver struct{}

func (unboundResolver) nicIDByName(string) tcpip.NICID { return 0 }

func (unboundResolver) nicIsLoopback(tcpip.NICID) bool { return false }

func (unboundResolver) addressAssigned(tcpip.NICID, tcpip.NetworkProtocolNumber, tcpip.Address) bool {
	return false
}

func (unboundResolver) subnetBroadcast(tcpip.NICID, tcpip.NetworkProtocolNumber, tcpip.Address) bool {
	return false
}

// stackBinder is implemented by matchers that need the Stack at match time.
// The parsed rule does not carry the Stack, because stack.Matcher.Match gets
// only the packet.
type stackBinder interface {
	bindStack(stk *stack.Stack)
}

// bindMatcherStacks gives the Stack to every matcher in rules that needs it.
func bindMatcherStacks(stk *stack.Stack, rules []stack.Rule) {
	for _, rule := range rules {
		for _, m := range rule.Matchers {
			if b, ok := m.(stackBinder); ok {
				b.bindStack(stk)
			}
		}
	}
}
