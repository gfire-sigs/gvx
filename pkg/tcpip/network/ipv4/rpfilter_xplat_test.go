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

package ipv4_test

import (
	"testing"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const rpMarkedTable = 100

var (
	rpEth0Addr = tcpip.AddrFrom4([4]byte{10, 0, 1, 1})
	rpEth1Addr = tcpip.AddrFrom4([4]byte{10, 0, 2, 1})
	// rpRemote is reachable through eth0 in the table main and through eth1 in
	// the table of the mark 5.
	rpRemote = tcpip.AddrFrom4([4]byte{10, 1, 0, 5})
	// rpNoRoute has no route.
	rpNoRoute = tcpip.AddrFrom4([4]byte{172, 16, 0, 5})
)

// rpHost is a stack with eth0 (NIC 1) and eth1 (NIC 2) and a reverse path
// policy that each test sets.
type rpHost struct {
	s    *stack.Stack
	eps  map[tcpip.NICID]*channel.Endpoint
	addr map[tcpip.NICID]tcpip.Address
	// all, link, and srcValidMark are the settings that the policy reports.
	all          int32
	link         map[tcpip.NICID]int32
	srcValidMark bool
}

func newRPHost(t *testing.T) *rpHost {
	t.Helper()
	h := &rpHost{
		s:    stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}}),
		eps:  map[tcpip.NICID]*channel.Endpoint{},
		addr: map[tcpip.NICID]tcpip.Address{1: rpEth0Addr, 2: rpEth1Addr},
		link: map[tcpip.NICID]int32{},
	}
	t.Cleanup(h.s.Close)
	for id, addr := range h.addr {
		h.eps[id] = channel.New(4, 1500, "")
		if err := h.s.CreateNIC(id, h.eps[id]); err != nil {
			t.Fatalf("CreateNIC(%d): %v", id, err)
		}
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}
		if err := h.s.AddProtocolAddress(id, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", id, err)
		}
	}
	subnet := func(a, b, c byte, prefix int) tcpip.Subnet {
		return tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{a, b, c, 0}), PrefixLen: prefix}.Subnet()
	}
	h.s.SetRouteTable([]tcpip.Route{
		{Destination: subnet(10, 0, 1, 24), NIC: 1},
		{Destination: subnet(10, 0, 2, 24), NIC: 2},
		{Destination: subnet(10, 1, 0, 24), NIC: 1},
		{Destination: subnet(10, 1, 0, 24), NIC: 2, RouteAttrs: tcpip.RouteAttrs{Table: rpMarkedTable}},
	})
	rule := stack.PolicyRule{Priority: 100, Action: stack.RuleActionToTable, Table: rpMarkedTable, Mark: 5, MarkMask: 0xffffffff, SuppressPrefixLen: -1}
	if err := h.s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	h.s.SetRPFilterPolicy(func(nic tcpip.NICID) (int32, bool) {
		return max(h.all, h.link[nic]), h.srcValidMark
	})
	return h
}

// dropped injects a packet on the NIC and reports whether the stack counted it
// as a packet with an invalid source address.
func (h *rpHost) dropped(t *testing.T, nic tcpip.NICID, src, dst tcpip.Address, mark uint32, proto tcpip.TransportProtocolNumber) bool {
	t.Helper()
	before := h.s.Stats().IP.InvalidSourceAddressesReceived.Value()
	b := make([]byte, header.IPv4MinimumSize)
	header.IPv4(b).Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		TTL:         64,
		Protocol:    uint8(proto),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip := header.IPv4(b)
	ip.SetChecksum(^ip.CalculateChecksum())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	pkt.Mark = mark
	h.eps[nic].InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
	return h.s.Stats().IP.InvalidSourceAddressesReceived.Value() > before
}

func TestRPFilterModes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		all       int32
		link      map[tcpip.NICID]int32
		nic       tcpip.NICID
		src       tcpip.Address
		wantDrops bool
	}{
		{"off accepts a spoofed source", 0, nil, 2, rpRemote, false},
		{"off accepts an unrouted source", 0, nil, 2, rpNoRoute, false},
		{"strict accepts the source on its interface", 0, map[tcpip.NICID]int32{1: 1}, 1, rpRemote, false},
		{"strict drops the source on another interface", 0, map[tcpip.NICID]int32{2: 1}, 2, rpRemote, true},
		{"strict drops an unrouted source", 0, map[tcpip.NICID]int32{2: 1}, 2, rpNoRoute, true},
		{"loose accepts the source on another interface", 0, map[tcpip.NICID]int32{2: 2}, 2, rpRemote, false},
		{"loose drops an unrouted source", 0, map[tcpip.NICID]int32{2: 2}, 2, rpNoRoute, true},
		{"all strict applies to a link at 0", 1, nil, 2, rpRemote, true},
		{"all loose applies to a link at 0", 2, nil, 2, rpRemote, false},
		{"the larger value wins: all 2, link 1", 2, map[tcpip.NICID]int32{2: 1}, 2, rpRemote, false},
		{"the larger value wins: all 1, link 2", 1, map[tcpip.NICID]int32{2: 2}, 2, rpRemote, false},
		{"the larger value wins: all 0, link 2", 0, map[tcpip.NICID]int32{2: 2}, 2, rpRemote, false},
		{"a link at 1 leaves the other link alone", 0, map[tcpip.NICID]int32{1: 1}, 2, rpRemote, false},
		{"a value above 2 turns the check off", 0, map[tcpip.NICID]int32{2: 3}, 2, rpRemote, false},
		{"strict drops an address of the host", 0, map[tcpip.NICID]int32{2: 1}, 2, rpEth0Addr, true},
		{"loose drops an address of the host", 0, map[tcpip.NICID]int32{2: 2}, 2, rpEth0Addr, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRPHost(t)
			h.all, h.link = tc.all, tc.link
			if h.link == nil {
				h.link = map[tcpip.NICID]int32{}
			}
			if got := h.dropped(t, tc.nic, tc.src, h.addr[tc.nic], 0, header.UDPProtocolNumber); got != tc.wantDrops {
				t.Errorf("packet from %s on NIC %d dropped = %t, want %t", tc.src, tc.nic, got, tc.wantDrops)
			}
		})
	}
}

// TestRPFilterUsesTheMarkOnlyWithSrcValidMark checks the flow of the lookup.
// The rule of the mark 5 sends the route to the remote through eth1. The strict
// check accepts the packet on eth1 only when src_valid_mark is on.
func TestRPFilterUsesTheMarkOnlyWithSrcValidMark(t *testing.T) {
	for _, tc := range []struct {
		name         string
		srcValidMark bool
		mark         uint32
		nic          tcpip.NICID
		wantDrops    bool
	}{
		{"mark ignored: marked packet on eth1", false, 5, 2, true},
		{"mark ignored: marked packet on eth0", false, 5, 1, false},
		{"mark used: marked packet on eth1", true, 5, 2, false},
		{"mark used: marked packet on eth0", true, 5, 1, true},
		{"mark used: unmarked packet on eth0", true, 0, 1, false},
		{"mark used: unmarked packet on eth1", true, 0, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRPHost(t)
			h.all, h.srcValidMark = 1, tc.srcValidMark
			if got := h.dropped(t, tc.nic, rpRemote, h.addr[tc.nic], tc.mark, header.UDPProtocolNumber); got != tc.wantDrops {
				t.Errorf("packet with mark %d on NIC %d dropped = %t, want %t", tc.mark, tc.nic, got, tc.wantDrops)
			}
		})
	}
}

// TestRPFilterUnspecifiedSource checks the cases of fib_validate_source() and
// ip_route_input_slow() of Linux for the source 0.0.0.0 with the strict check.
func TestRPFilterUnspecifiedSource(t *testing.T) {
	unspecified := tcpip.AddrFrom4([4]byte{})
	for _, tc := range []struct {
		name      string
		dst       tcpip.Address
		proto     tcpip.TransportProtocolNumber
		wantDrops bool
	}{
		{"limited broadcast", header.IPv4Broadcast, header.UDPProtocolNumber, false},
		{"link-local multicast", header.IPv4AllSystems, header.UDPProtocolNumber, false},
		{"IGMP to other multicast", tcpip.AddrFrom4([4]byte{239, 1, 1, 1}), header.IGMPProtocolNumber, false},
		{"other multicast", tcpip.AddrFrom4([4]byte{239, 1, 1, 1}), header.UDPProtocolNumber, true},
		{"unicast", rpEth0Addr, header.UDPProtocolNumber, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRPHost(t)
			h.all = 1
			if got := h.dropped(t, 1, unspecified, tc.dst, 0, tc.proto); got != tc.wantDrops {
				t.Errorf("packet from 0.0.0.0 to %s dropped = %t, want %t", tc.dst, got, tc.wantDrops)
			}
		})
	}
}

// TestRPFilterWithoutPolicyChecksNothing checks that a stack without a policy
// keeps the behavior that it had before.
func TestRPFilterWithoutPolicyChecksNothing(t *testing.T) {
	h := newRPHost(t)
	h.s.SetRPFilterPolicy(nil)
	if h.dropped(t, 2, rpNoRoute, rpEth1Addr, 0, header.UDPProtocolNumber) {
		t.Error("a stack without a policy dropped a packet")
	}
}
