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
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// icmpEntry returns the bytes of one xt_entry_match that userspace builds for
// the icmp or icmp6 match: struct ipt_icmp with type, code range, and invflags.
func icmpEntry(name string, icmpType, codeLow, codeHigh, invflags uint8) []byte {
	return marshalEntryMatch(name, []byte{icmpType, codeLow, codeHigh, invflags})
}

// icmpPacketSpec describes the packet that the Match tests build.
type icmpPacketSpec struct {
	ipv6     bool
	protocol uint8
	typ      uint8
	code     uint8
	// fragOffset is the IPv4 fragment offset in bytes.
	fragOffset uint16
	// headerBytes is the length of the transport header in the packet. A
	// value below 8 makes a truncated ICMP header.
	headerBytes int
	// inData puts the ICMP bytes in the data of the packet and leaves the
	// transport header empty, as for a packet that no layer parsed.
	inData bool
}

func buildICMPPacket(t *testing.T, spec icmpPacketSpec) *stack.PacketBuffer {
	t.Helper()
	icmp := make([]byte, icmpHeaderSize)
	icmp[0], icmp[1] = spec.typ, spec.code
	if spec.headerBytes == 0 {
		spec.headerBytes = icmpHeaderSize
	}
	icmp = icmp[:spec.headerBytes]

	var netHeader []byte
	if spec.ipv6 {
		netHeader = make([]byte, header.IPv6MinimumSize)
		header.IPv6(netHeader).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(icmp)),
			TransportProtocol: tcpip.TransportProtocolNumber(spec.protocol),
			HopLimit:          64,
			SrcAddr:           matchPeer6,
			DstAddr:           matchLocal6,
		})
	} else {
		netHeader = make([]byte, header.IPv4MinimumSize)
		header.IPv4(netHeader).Encode(&header.IPv4Fields{
			TotalLength:    uint16(len(netHeader) + len(icmp)),
			Protocol:       spec.protocol,
			TTL:            64,
			FragmentOffset: spec.fragOffset,
			SrcAddr:        matchPeer4,
			DstAddr:        matchLocal4,
		})
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append(bytes.Clone(netHeader), icmp...))})
	t.Cleanup(pkt.DecRef)
	if _, ok := pkt.NetworkHeader().Consume(len(netHeader)); !ok {
		t.Fatalf("cannot consume the network header")
	}
	if spec.ipv6 {
		pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
		pkt.TransportProtocolNumber = tcpip.TransportProtocolNumber(spec.protocol)
	} else {
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	}
	if !spec.inData {
		if _, ok := pkt.TransportHeader().Consume(len(icmp)); !ok {
			t.Fatalf("cannot consume the transport header")
		}
		if !spec.ipv6 {
			pkt.TransportProtocolNumber = tcpip.TransportProtocolNumber(spec.protocol)
		}
	}
	return pkt
}

func TestICMPMatch(t *testing.T) {
	const (
		echoRequest = 8
		unreachable = 3
		invert      = icmpInvert
	)
	v4 := icmpPacketSpec{protocol: uint8(header.ICMPv4ProtocolNumber)}
	v6 := icmpPacketSpec{ipv6: true, protocol: uint8(header.ICMPv6ProtocolNumber)}
	with := func(spec icmpPacketSpec, f func(*icmpPacketSpec)) icmpPacketSpec {
		f(&spec)
		return spec
	}
	typeCode := func(spec icmpPacketSpec, typ, code uint8) icmpPacketSpec {
		return with(spec, func(s *icmpPacketSpec) { s.typ, s.code = typ, code })
	}

	tests := []struct {
		name        string
		matchName   string
		icmpType    uint8
		codeLow     uint8
		codeHigh    uint8
		invflags    uint8
		packet      icmpPacketSpec
		wantMatch   bool
		wantHotdrop bool
	}{
		{"icmp type and code hit", "icmp", echoRequest, 0, 0, 0, typeCode(v4, echoRequest, 0), true, false},
		{"icmp other type", "icmp", echoRequest, 0, 0, 0, typeCode(v4, unreachable, 0), false, false},
		{"icmp code inside the range", "icmp", unreachable, 1, 5, 0, typeCode(v4, unreachable, 3), true, false},
		{"icmp code at the low end", "icmp", unreachable, 1, 5, 0, typeCode(v4, unreachable, 1), true, false},
		{"icmp code at the high end", "icmp", unreachable, 1, 5, 0, typeCode(v4, unreachable, 5), true, false},
		{"icmp code below the range", "icmp", unreachable, 1, 5, 0, typeCode(v4, unreachable, 0), false, false},
		{"icmp code above the range", "icmp", unreachable, 1, 5, 0, typeCode(v4, unreachable, 6), false, false},
		{"icmp inverted hit", "icmp", echoRequest, 0, 255, invert, typeCode(v4, echoRequest, 0), false, false},
		{"icmp inverted miss", "icmp", echoRequest, 0, 255, invert, typeCode(v4, unreachable, 0), true, false},
		{"icmp any type", "icmp", 0xFF, 0, 255, 0, typeCode(v4, 13, 7), true, false},
		{"icmp any type inverted", "icmp", 0xFF, 0, 255, invert, typeCode(v4, 13, 7), false, false},
		{"icmp skips another protocol", "icmp", 0xFF, 0, 255, 0, with(typeCode(v4, 8, 0), func(s *icmpPacketSpec) { s.protocol = uint8(header.UDPProtocolNumber) }), false, false},
		{"icmp skips a fragment with an offset", "icmp", echoRequest, 0, 0, 0, with(typeCode(v4, echoRequest, 0), func(s *icmpPacketSpec) { s.fragOffset = 8 }), false, false},
		{"icmp skips a fragment with an offset even when inverted", "icmp", echoRequest, 0, 0, invert, with(typeCode(v4, unreachable, 0), func(s *icmpPacketSpec) { s.fragOffset = 8 }), false, false},
		{"icmp drops a truncated header", "icmp", 0xFF, 0, 255, 0, with(typeCode(v4, 8, 0), func(s *icmpPacketSpec) { s.headerBytes = 4 }), false, true},
		{"icmp reads the header from the data", "icmp", echoRequest, 0, 0, 0, with(typeCode(v4, echoRequest, 0), func(s *icmpPacketSpec) { s.inData = true }), true, false},
		{"icmp drops a truncated header in the data", "icmp", 0xFF, 0, 255, 0, with(typeCode(v4, 8, 0), func(s *icmpPacketSpec) { s.inData, s.headerBytes = true, 4 }), false, true},

		{"icmp6 type and code hit", "icmp6", 128, 0, 0, 0, typeCode(v6, 128, 0), true, false},
		{"icmp6 other type", "icmp6", 128, 0, 0, 0, typeCode(v6, 129, 0), false, false},
		{"icmp6 code inside the range", "icmp6", 1, 0, 4, 0, typeCode(v6, 1, 4), true, false},
		{"icmp6 code above the range", "icmp6", 1, 0, 4, 0, typeCode(v6, 1, 5), false, false},
		{"icmp6 inverted hit", "icmp6", 128, 0, 255, invert, typeCode(v6, 128, 0), false, false},
		{"icmp6 inverted miss", "icmp6", 128, 0, 255, invert, typeCode(v6, 129, 0), true, false},
		// WHY: icmp6_type_code_match of Linux has no wildcard. The value 0xFF is a type.
		{"icmp6 type 0xFF is no wildcard", "icmp6", 0xFF, 0, 255, 0, typeCode(v6, 128, 0), false, false},
		{"icmp6 type 0xFF inverted", "icmp6", 0xFF, 0, 255, invert, typeCode(v6, 128, 0), true, false},
		{"icmp6 skips another protocol", "icmp6", 128, 0, 255, 0, with(typeCode(v6, 128, 0), func(s *icmpPacketSpec) { s.protocol = uint8(header.UDPProtocolNumber) }), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := icmpFilter(tc.packet.ipv6)
			m := parseOneMatcher(t, filter, icmpEntry(tc.matchName, tc.icmpType, tc.codeLow, tc.codeHigh, tc.invflags))
			pkt := buildICMPPacket(t, tc.packet)
			gotMatch, gotHotdrop := m.Match(stack.Input, pkt, "eth0", "")
			if gotMatch != tc.wantMatch || gotHotdrop != tc.wantHotdrop {
				t.Errorf("Match = (%v, hotdrop %v), want (%v, hotdrop %v)", gotMatch, gotHotdrop, tc.wantMatch, tc.wantHotdrop)
			}
		})
	}
}

func TestICMPMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		matchName string
		ipv6      bool
		entry     []byte
	}{
		{"icmp echo-request", "icmp", false, icmpEntry("icmp", 8, 0, 0, 0)},
		{"icmp code range inverted", "icmp", false, icmpEntry("icmp", 3, 1, 13, icmpInvert)},
		{"icmp any", "icmp", false, icmpEntry("icmp", 0xFF, 0, 255, 0)},
		{"icmp6 echo-request", "icmp6", true, icmpEntry("icmp6", 128, 0, 255, 0)},
		{"icmp6 inverted", "icmp6", true, icmpEntry("icmp6", 1, 0, 4, icmpInvert)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parseOneMatcher(t, icmpFilter(tc.ipv6), tc.entry)
			if _, ok := m.(*ICMPMatcher); !ok {
				t.Fatalf("parseMatchers returned %T, want *ICMPMatcher", m)
			}
			got := marshalMatcher(m)
			if !bytes.Equal(got, tc.entry) {
				t.Errorf("marshalMatcher = %x, want %x", got, tc.entry)
			}
			var hdr linux.XTEntryMatch
			hdr.UnmarshalBytes(got)
			if hdr.Name.String() != tc.matchName || int(hdr.MatchSize) != len(got) || len(got)%8 != 0 {
				t.Errorf("header = name %q size %d for %d bytes, want name %q and an 8-byte aligned size", hdr.Name.String(), hdr.MatchSize, len(got), tc.matchName)
			}
		})
	}
}

func TestICMPUnmarshalRejects(t *testing.T) {
	udp4 := stack.EmptyFilter4()
	udp4.Protocol, udp4.CheckProtocol = header.UDPProtocolNumber, true
	noProto4 := stack.EmptyFilter4()
	tests := []struct {
		name   string
		filter stack.IPHeaderFilter
		entry  []byte
	}{
		{"invalid invflags", icmpFilter(false), icmpEntry("icmp", 8, 0, 0, 2)},
		{"too long", icmpFilter(false), marshalEntryMatch("icmp", make([]byte, 12))},
		{"icmp in a UDP rule", udp4, icmpEntry("icmp", 8, 0, 0, 0)},
		{"icmp in a rule without protocol", noProto4, icmpEntry("icmp", 8, 0, 0, 0)},
		{"icmp in an IPv6 rule", icmpFilter(true), icmpEntry("icmp", 8, 0, 0, 0)},
		{"icmp6 in an IPv4 rule", icmpFilter(false), icmpEntry("icmp6", 128, 0, 0, 0)},
		{"icmp6 with the ICMP protocol", func() stack.IPHeaderFilter {
			f := stack.EmptyFilter6()
			f.Protocol, f.CheckProtocol = header.ICMPv4ProtocolNumber, true
			return f
		}(), icmpEntry("icmp6", 128, 0, 0, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMatchers(nil, tc.filter, tc.entry); err == nil {
				t.Errorf("parseMatchers accepted the match")
			}
		})
	}
}

func TestICMPMatchRevisionIsReported(t *testing.T) {
	for _, name := range []string{"icmp", "icmp6"} {
		if rev, ok := matchMakerRevision(name, 0); !ok || rev != 0 {
			t.Errorf("matchMakerRevision(%q) = (%d, %v), want (0, true)", name, rev, ok)
		}
	}
}

// TestICMPRuleFiltersEchoRequests sends echo requests through the INPUT chain
// of a stack. A rule with the icmp or icmp6 match that drops the request
// removes the echo reply.
func TestICMPRuleFiltersEchoRequests(t *testing.T) {
	tests := []struct {
		name      string
		ipv6      bool
		matchName string
		icmpType  uint8
		codeLow   uint8
		codeHigh  uint8
		invflags  uint8
		wantReply bool
	}{
		{"icmp echo-request drops", false, "icmp", 8, 0, 255, 0, false},
		{"icmp destination-unreachable lets it through", false, "icmp", 3, 0, 255, 0, true},
		{"icmp not echo-request lets it through", false, "icmp", 8, 0, 255, icmpInvert, true},
		{"icmp not destination-unreachable drops", false, "icmp", 3, 0, 255, icmpInvert, false},
		{"icmp any drops", false, "icmp", 0xFF, 0, 255, 0, false},
		{"icmp echo-request with another code lets it through", false, "icmp", 8, 1, 255, 0, true},
		{"icmpv6 echo-request drops", true, "icmp6", 128, 0, 255, 0, false},
		{"icmpv6 destination-unreachable lets it through", true, "icmp6", 1, 0, 255, 0, true},
		{"icmpv6 not echo-request lets it through", true, "icmp6", 128, 0, 255, icmpInvert, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ms := newMatchStack(t)
			if !ms.injectEchoRequest(t, tc.ipv6) {
				t.Fatalf("the stack sent no echo reply before the rule")
			}
			filter := icmpFilter(tc.ipv6)
			m := parseOneMatcher(t, filter, icmpEntry(tc.matchName, tc.icmpType, tc.codeLow, tc.codeHigh, tc.invflags))
			ms.installRules(t, tc.ipv6, stack.Input, dropRule(filter, m))
			if got := ms.injectEchoRequest(t, tc.ipv6); got != tc.wantReply {
				t.Errorf("echo reply = %v, want %v", got, tc.wantReply)
			}
		})
	}
}
