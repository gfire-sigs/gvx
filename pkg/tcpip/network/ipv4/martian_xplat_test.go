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
