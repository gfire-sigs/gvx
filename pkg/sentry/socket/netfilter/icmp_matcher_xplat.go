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

	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "icmp" and "icmp6" matches
// (icmp_match and icmp6_match in net/netfilter/xt_tcpudp.c). A rule such as
// "-p icmp --icmp-type echo-request" or "-p icmpv6 --icmpv6-type 128" selects
// ICMP packets by type and code. kube-router and Calico use these rules.
// Ref: struct ipt_icmp in include/uapi/linux/netfilter_ipv4/ip_tables.h and
// struct ip6t_icmp in include/uapi/linux/netfilter_ipv6/ip6_tables.h.

const (
	matcherNameICMP  = "icmp"
	matcherNameICMP6 = "icmp6"

	// icmpInfoSize is sizeof(struct ipt_icmp) and sizeof(struct ip6t_icmp):
	// type, code[2], and invflags.
	icmpInfoSize = 4

	// icmpInvert is IPT_ICMP_INV and IP6T_ICMP_INV. Linux rejects every other
	// bit of invflags.
	icmpInvert uint8 = 1

	// icmpAnyType is the type value of "--icmp-type any". Only the IPv4 match
	// treats it as a wildcard.
	icmpAnyType uint8 = 0xFF

	// icmpHeaderSize is sizeof(struct icmphdr) and sizeof(struct icmp6hdr). A
	// packet with less bytes of ICMP header makes the match drop it.
	icmpHeaderSize = 8
)

func init() {
	registerMatchMaker(icmpMarshaler{ipv6: false})
	registerMatchMaker(icmpMarshaler{ipv6: true})
}

// icmpMarshaler implements matchMaker for the icmp match of IPv4 rules and the
// icmp6 match of IPv6 rules.
type icmpMarshaler struct {
	ipv6 bool
}

// name implements matchMaker.name.
func (m icmpMarshaler) name() string {
	if m.ipv6 {
		return matcherNameICMP6
	}
	return matcherNameICMP
}

// revision implements matchMaker.revision.
func (icmpMarshaler) revision() uint8 { return 0 }

// marshal implements matchMaker.marshal.
func (m icmpMarshaler) marshal(mr matcher) []byte {
	im := mr.(*ICMPMatcher)
	data := []byte{im.icmpType, im.code[0], im.code[1], im.invflags}
	return marshalEntryMatch(m.name(), data)
}

// unmarshal implements matchMaker.unmarshal. It applies the checks of
// xt_check_match and of icmp_checkentry.
func (m icmpMarshaler) unmarshal(_ IDMapper, _ *stack.Stack, buf []byte, filter stack.IPHeaderFilter) (stack.Matcher, error) {
	// WHY: Linux requires the exact aligned size.
	if want := bits.AlignUp(icmpInfoSize, 8); len(buf) != want {
		return nil, fmt.Errorf("%s: buf has size %d, want %d", m.name(), len(buf), want)
	}
	wantNetwork, wantProto := header.IPv4ProtocolNumber, header.ICMPv4ProtocolNumber
	if m.ipv6 {
		wantNetwork, wantProto = header.IPv6ProtocolNumber, header.ICMPv6ProtocolNumber
	}
	// A match of the other family does not exist in Linux. xt_check_match
	// also rejects a rule whose protocol is not ICMP or whose protocol test is
	// inverted. The parser of the rule already rejects an inverted protocol.
	if filter.NetworkProtocol() != wantNetwork {
		return nil, fmt.Errorf("%s: match is only valid for network protocol %d", m.name(), wantNetwork)
	}
	if !filter.CheckProtocol || filter.Protocol != wantProto {
		return nil, fmt.Errorf("%s: match is only valid for protocol %d", m.name(), wantProto)
	}
	im := &ICMPMatcher{
		ipv6:     m.ipv6,
		icmpType: buf[0],
		code:     [2]uint8{buf[1], buf[2]},
		invflags: buf[3],
	}
	if im.invflags&^icmpInvert != 0 {
		return nil, fmt.Errorf("%s: invalid invflags 0x%x", m.name(), im.invflags)
	}
	nflog("parsed %s: type %d code %v invflags 0x%x", m.name(), im.icmpType, im.code, im.invflags)
	return im, nil
}

// ICMPMatcher matches ICMP and ICMPv6 packets by type and code range.
//
// +stateify savable
type ICMPMatcher struct {
	ipv6     bool
	icmpType uint8
	// code holds the first and the last code of the range.
	code     [2]uint8
	invflags uint8
}

// name implements matcher.name.
func (im *ICMPMatcher) name() string {
	if im.ipv6 {
		return matcherNameICMP6
	}
	return matcherNameICMP
}

// revision implements matcher.revision.
func (*ICMPMatcher) revision() uint8 { return 0 }

// Match implements stack.Matcher.Match. It follows icmp_match and
// icmp6_match.
func (im *ICMPMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if im.ipv6 {
			return false, false
		}
		netHeader := header.IPv4(pkt.NetworkHeader().Slice())
		if netHeader.TransportProtocol() != header.ICMPv4ProtocolNumber {
			return false, false
		}
		// Linux does not match a fragment with an offset, even with the
		// inversion flag.
		if netHeader.FragmentOffset() != 0 {
			return false, false
		}
	case header.IPv6ProtocolNumber:
		if !im.ipv6 || pkt.TransportProtocolNumber != header.ICMPv6ProtocolNumber {
			return false, false
		}
	default:
		return false, false
	}

	icmpHeader, ok := transportPrefix(pkt, icmpHeaderSize)
	if !ok {
		// The packet claims ICMP but has no full header. Linux cannot examine
		// it, so it drops the packet.
		return false, true
	}
	return im.matchTypeCode(icmpHeader[0], icmpHeader[1]), false
}

// matchTypeCode applies icmp_type_code_match and icmp6_type_code_match.
func (im *ICMPMatcher) matchTypeCode(typ, code uint8) bool {
	invert := im.invflags&icmpInvert != 0
	if !im.ipv6 && im.icmpType == icmpAnyType {
		return !invert
	}
	inRange := typ == im.icmpType && code >= im.code[0] && code <= im.code[1]
	return inRange != invert
}

// transportPrefix returns the first n bytes of the transport header of pkt. An
// IPv4 first fragment and a packet that no layer parsed have no transport
// header yet. Their transport bytes start the data of the packet, as the
// skb_header_pointer call of Linux finds them. The caller must not keep or
// change the slice.
func transportPrefix(pkt *stack.PacketBuffer, n int) ([]byte, bool) {
	if h := pkt.TransportHeader().Slice(); len(h) > 0 {
		return h, len(h) >= n
	}
	return pkt.Data().PullUp(n)
}
