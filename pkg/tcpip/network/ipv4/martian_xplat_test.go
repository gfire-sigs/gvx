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
	"bytes"
	"context"
	"testing"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// martianSetter is the per-endpoint route_localnet of the IPv4 endpoint.
type martianSetter interface {
	SetAllowMartianLoopback(bool)
	AllowMartianLoopback() bool
}

func TestRouteLocalnetOfOneEndpointLeavesOtherEndpointsFiltered(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	nics := []tcpip.NICID{1, 2}
	eps := make(map[tcpip.NICID]*channel.Endpoint)
	addrs := map[tcpip.NICID]tcpip.Address{1: tcpip.AddrFrom4([4]byte{192, 168, 1, 1}), 2: tcpip.AddrFrom4([4]byte{192, 168, 2, 1})}
	for _, id := range nics {
		eps[id] = channel.New(4, 1500, "")
		if err := s.CreateNIC(id, eps[id]); err != nil {
			t.Fatalf("CreateNIC(%d): %v", id, err)
		}
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addrs[id], PrefixLen: 24}}
		if err := s.AddProtocolAddress(id, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", id, err)
		}
	}

	// dropped injects a packet with a loopback source and reports whether the
	// endpoint counted it as a martian packet.
	dropped := func(id tcpip.NICID) bool {
		t.Helper()
		before := s.Stats().IP.InvalidSourceAddressesReceived.Value()
		b := make([]byte, header.IPv4MinimumSize)
		header.IPv4(b).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			DstAddr:     addrs[id],
		})
		ip := header.IPv4(b)
		ip.SetChecksum(^ip.CalculateChecksum())
		eps[id].InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)}))
		return s.Stats().IP.InvalidSourceAddressesReceived.Value() > before
	}
	setter := func(id tcpip.NICID) martianSetter {
		t.Helper()
		ep, err := s.GetNetworkEndpoint(id, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("GetNetworkEndpoint(%d): %v", id, err)
		}
		return ep.(martianSetter)
	}

	if !dropped(1) || !dropped(2) {
		t.Fatal("a loopback source on a non-loopback endpoint is accepted by default, want a martian drop")
	}
	setter(1).SetAllowMartianLoopback(true)
	if dropped(1) {
		t.Error("endpoint 1 dropped a loopback source after route_localnet was on")
	}
	if !dropped(2) {
		t.Error("endpoint 2 accepted a loopback source after route_localnet was set on endpoint 1 only")
	}
	if setter(2).AllowMartianLoopback() {
		t.Error("endpoint 2 reports route_localnet after a write to endpoint 1")
	}
	setter(1).SetAllowMartianLoopback(false)
	if !dropped(1) {
		t.Error("endpoint 1 accepted a loopback source after route_localnet was off")
	}
}

func TestAllowMartianLoopbackSurvivesSaveLoad(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer s.Close()

	addrs := map[tcpip.NICID]tcpip.Address{
		1: tcpip.AddrFrom4([4]byte{192, 168, 10, 1}),
		2: tcpip.AddrFrom4([4]byte{192, 168, 20, 1}),
	}
	for _, id := range []tcpip.NICID{1, 2} {
		ep := channel.New(4, 1500, "")
		if err := s.CreateNICWithOptions(id, ep, stack.NICOptions{Kind: "tun"}); err != nil {
			t.Fatalf("CreateNICWithOptions(%d): %v", id, err)
		}
		pa := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: addrs[id], PrefixLen: 24},
		}
		if err := s.AddProtocolAddress(id, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", id, err)
		}
	}

	ep1, err := s.GetNetworkEndpoint(1, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("GetNetworkEndpoint(1): %v", err)
	}
	ep1.(martianSetter).SetAllowMartianLoopback(true)

	ctx := context.Background()
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &s); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restored *stack.Stack
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer restored.Close()
	restored.SetIPTables(stack.DefaultTables(restored.Clock(), restored.InsecureRNG()))
	restored.Restore()

	for _, tc := range []struct {
		id       tcpip.NICID
		wantFlag bool
		wantDrop bool
	}{
		{id: 1, wantFlag: true, wantDrop: false},
		{id: 2, wantFlag: false, wantDrop: true},
	} {
		netEP, err := restored.GetNetworkEndpoint(tc.id, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("restored GetNetworkEndpoint(%d): %v", tc.id, err)
		}
		if got := netEP.(martianSetter).AllowMartianLoopback(); got != tc.wantFlag {
			t.Errorf("restored endpoint %d AllowMartianLoopback = %t, want %t", tc.id, got, tc.wantFlag)
		}

		before := restored.Stats().IP.InvalidSourceAddressesReceived.Value()
		b := make([]byte, header.IPv4MinimumSize)
		header.IPv4(b).Encode(&header.IPv4Fields{
			TotalLength: header.IPv4MinimumSize,
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			DstAddr:     addrs[tc.id],
		})
		ip := header.IPv4(b)
		ip.SetChecksum(^ip.CalculateChecksum())
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		netEP.HandlePacket(pkt)
		pkt.DecRef()

		dropped := restored.Stats().IP.InvalidSourceAddressesReceived.Value() > before
		if dropped != tc.wantDrop {
			t.Errorf("restored endpoint %d martian drop = %t, want %t", tc.id, dropped, tc.wantDrop)
		}
	}
}
