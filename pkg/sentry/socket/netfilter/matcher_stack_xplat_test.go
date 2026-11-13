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
	"net/netip"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// The helpers of this file serve the tests of the icmp, icmp6, limit, and
// NFLOG extensions. They build a stack with one NIC that has no link layer,
// inject ICMP echo requests into it, and tell whether the stack sent an echo
// reply. A rule in the INPUT chain that drops the request removes the reply.

var (
	matchLocal4 = tcpip.AddrFrom4(netip.MustParseAddr("10.0.0.1").As4())
	matchPeer4  = tcpip.AddrFrom4(netip.MustParseAddr("10.0.0.2").As4())
	matchLocal6 = tcpip.AddrFrom16(netip.MustParseAddr("fd00::1").As16())
	matchPeer6  = tcpip.AddrFrom16(netip.MustParseAddr("fd00::2").As16())
)

// matchStack is a stack with the address 10.0.0.1 and fd00::1 on one NIC.
type matchStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	clock *faketime.ManualClock
}

func newMatchStack(t *testing.T) *matchStack {
	t.Helper()
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            clock,
	})
	t.Cleanup(s.Close)
	ep := channel.New(16, 1500, "")
	if err := s.CreateNICWithOptions(1, ep, stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	for _, pa := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: matchLocal4, PrefixLen: 24}},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: matchLocal6, PrefixLen: 64}},
	} {
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%v): %v", pa.AddressWithPrefix, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	m := &matchStack{stack: s, ep: ep, clock: clock}
	// Drop the packets that the NIC sent while it came up.
	m.drainEchoReply(false)
	return m
}

// insertChainRules returns table with rules at the start of the chain of hook.
func insertChainRules(table stack.Table, hook stack.Hook, rules []stack.Rule) stack.Table {
	at := table.BuiltinChains[hook]
	table.Rules = slices.Concat(table.Rules[:at], rules, table.Rules[at:])
	for h := range table.BuiltinChains {
		if h != int(hook) && table.BuiltinChains[h] >= at {
			table.BuiltinChains[h] += len(rules)
		}
		if table.Underflows[h] >= at {
			table.Underflows[h] += len(rules)
		}
	}
	return table
}

// installRules puts rules at the start of the chain of hook in the filter
// table. It binds the matchers to the stack, as SetEntries does.
func (m *matchStack) installRules(t *testing.T, ipv6 bool, hook stack.Hook, rules ...stack.Rule) {
	t.Helper()
	table := insertChainRules(m.stack.IPTables().GetTable(stack.FilterID, ipv6), hook, rules)
	if err := bindMatcherStacks(m.stack, table.Rules); err != nil {
		t.Fatalf("bindMatcherStacks: %v", err)
	}
	m.stack.IPTables().ForceReplaceTable(stack.FilterID, table, ipv6)
}

// icmpFilter returns the header filter of a rule with "-p icmp" or
// "-p icmpv6".
func icmpFilter(ipv6 bool) stack.IPHeaderFilter {
	if ipv6 {
		f := stack.EmptyFilter6()
		f.Protocol, f.CheckProtocol = header.ICMPv6ProtocolNumber, true
		return f
	}
	f := stack.EmptyFilter4()
	f.Protocol, f.CheckProtocol = header.ICMPv4ProtocolNumber, true
	return f
}

// dropRule returns a rule that drops the packets which its matchers match.
func dropRule(filter stack.IPHeaderFilter, matchers ...stack.Matcher) stack.Rule {
	return stack.Rule{
		Filter:   filter,
		Matchers: matchers,
		Target:   &dropTarget{DropTarget: stack.DropTarget{NetworkProtocol: filter.NetworkProtocol()}},
	}
}

// parseOneMatcher parses the entries that userspace sends for one rule.
func parseOneMatcher(t *testing.T, filter stack.IPHeaderFilter, entry []byte) stack.Matcher {
	t.Helper()
	parsed, err := parseMatchers(nil, nil, filter, entry)
	if err != nil {
		t.Fatalf("parseMatchers: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parseMatchers returned %d matchers, want 1", len(parsed))
	}
	return parsed[0]
}

// injectEchoRequest sends an ICMP or ICMPv6 echo request from the peer to the
// stack and reports whether the stack answered with an echo reply.
func (m *matchStack) injectEchoRequest(t *testing.T, ipv6Packet bool) bool {
	t.Helper()
	var (
		frame []byte
		proto tcpip.NetworkProtocolNumber
	)
	if ipv6Packet {
		proto = ipv6.ProtocolNumber
		frame = make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize)
		header.IPv6(frame).Encode(&header.IPv6Fields{
			PayloadLength:     header.ICMPv6EchoMinimumSize,
			TransportProtocol: header.ICMPv6ProtocolNumber,
			HopLimit:          64,
			SrcAddr:           matchPeer6,
			DstAddr:           matchLocal6,
		})
		icmp := header.ICMPv6(frame[header.IPv6MinimumSize:])
		icmp.SetType(header.ICMPv6EchoRequest)
		icmp.SetIdent(1)
		icmp.SetSequence(1)
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmp, Src: matchPeer6, Dst: matchLocal6,
		}))
	} else {
		proto = ipv4.ProtocolNumber
		frame = make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
		ip := header.IPv4(frame)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(frame)),
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			TTL:         64,
			SrcAddr:     matchPeer4,
			DstAddr:     matchLocal4,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		icmp := header.ICMPv4(frame[header.IPv4MinimumSize:])
		icmp.SetType(header.ICMPv4Echo)
		icmp.SetIdent(1)
		icmp.SetSequence(1)
		icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	m.ep.InjectInbound(proto, pkt)

	return m.drainEchoReply(ipv6Packet)
}

// drainEchoReply reads every packet that the stack sent and reports whether
// one of them is an echo reply. The stack also sends packets of its own, such
// as IPv6 router solicitations.
func (m *matchStack) drainEchoReply(ipv6Packet bool) bool {
	found := false
	for pkt := m.ep.Read(); pkt != nil; pkt = m.ep.Read() {
		transport := pkt.TransportHeader().Slice()
		switch {
		case ipv6Packet && pkt.NetworkProtocolNumber == ipv6.ProtocolNumber && len(transport) > 0:
			found = found || header.ICMPv6(transport).Type() == header.ICMPv6EchoReply
		case !ipv6Packet && pkt.NetworkProtocolNumber == ipv4.ProtocolNumber && len(transport) > 0:
			found = found || header.ICMPv4(transport).Type() == header.ICMPv4EchoReply
		}
		pkt.DecRef()
	}
	return found
}
