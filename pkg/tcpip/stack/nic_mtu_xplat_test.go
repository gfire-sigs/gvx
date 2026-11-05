// Copyright 2018 The gVisor Authors.
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

package stack_test

import (
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const mtuTestNIC = tcpip.NICID(1)

var (
	mtuTestIPv6 = tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice([]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}).WithPrefix(),
	}
	mtuTestIPv4 = tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice([]byte{10, 0, 0, 1}).WithPrefix(),
	}
)

// newMTUTestStack returns a stack with one NIC that has MTU bounds, as a link
// that the guest can resize has. The NIC has an IPv4 address and an IPv6
// address, and it generates an IPv6 link-local address.
func newMTUTestStack(t *testing.T, mtu uint32, minMTU uint32) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocolWithOptions(ipv6.Options{AutoGenLinkLocal: true})},
	})
	t.Cleanup(func() { s.Close() })
	ep := channel.New(8, mtu, "\x02\x01\x02\x03\x04\x05")
	if err := s.CreateNICWithOptions(mtuTestNIC, ep, stack.NICOptions{Name: "eth0", MinMTU: minMTU, MaxMTU: 65535}); err != nil {
		t.Fatalf("CreateNICWithOptions: %v", err)
	}
	return s
}

// ipv6Addresses returns the permanent IPv6 unicast addresses of the test NIC.
func ipv6Addresses(s *stack.Stack) []tcpip.Address {
	var got []tcpip.Address
	for _, a := range s.AllAddresses()[mtuTestNIC] {
		if a.Protocol == ipv6.ProtocolNumber && header.IsV6UnicastAddress(a.AddressWithPrefix.Address) {
			got = append(got, a.AddressWithPrefix.Address)
		}
	}
	return got
}

func hasLinkLocal(addrs []tcpip.Address) bool {
	for _, a := range addrs {
		if header.IsV6LinkLocalUnicastAddress(a) {
			return true
		}
	}
	return false
}

func TestSetNICMTUBelow1280StopsIPv6UntilTheMTUReturns(t *testing.T) {
	s := newMTUTestStack(t, 1500, header.IPv4MinimumMTU)
	if err := s.AddProtocolAddress(mtuTestNIC, mtuTestIPv6, stack.AddressProperties{}); err != nil {
		t.Fatalf("add the IPv6 address: %v", err)
	}
	if err := s.AddProtocolAddress(mtuTestNIC, mtuTestIPv4, stack.AddressProperties{}); err != nil {
		t.Fatalf("add the IPv4 address: %v", err)
	}
	if err := s.EnableNIC(mtuTestNIC); err != nil {
		t.Fatalf("EnableNIC: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: mtuTestNIC})
	if got := ipv6Addresses(s); len(got) != 2 || !hasLinkLocal(got) {
		t.Fatalf("IPv6 addresses before the change = %v, want the global and the link-local address", got)
	}

	if err := s.SetNICMTU(mtuTestNIC, header.IPv6MinimumMTU-1); err != nil {
		t.Fatalf("SetNICMTU(1279): %v", err)
	}
	if got := ipv6Addresses(s); len(got) != 0 {
		t.Errorf("IPv6 addresses at MTU 1279 = %v, want none", got)
	}
	for _, r := range s.GetRouteTable() {
		if r.NIC == mtuTestNIC && r.Destination.ID().Len() == header.IPv6AddressSize {
			t.Errorf("IPv6 route %v stays at MTU 1279", r)
		}
	}
	if err := s.AddProtocolAddress(mtuTestNIC, mtuTestIPv6, stack.AddressProperties{}); err == nil {
		t.Error("AddProtocolAddress accepted an IPv6 address at MTU 1279")
	}
	var v4 bool
	for _, a := range s.AllAddresses()[mtuTestNIC] {
		v4 = v4 || a.Protocol == ipv4.ProtocolNumber && a.AddressWithPrefix == mtuTestIPv4.AddressWithPrefix
	}
	if !v4 {
		t.Error("the IPv4 address left with the IPv6 addresses")
	}

	if err := s.DisableNIC(mtuTestNIC); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableNIC(mtuTestNIC); err != nil {
		t.Fatal(err)
	}
	if got := ipv6Addresses(s); len(got) != 0 {
		t.Errorf("IPv6 addresses after a NIC down and up at MTU 1279 = %v, want none", got)
	}

	if err := s.SetNICMTU(mtuTestNIC, header.IPv6MinimumMTU); err != nil {
		t.Fatalf("SetNICMTU(1280): %v", err)
	}
	if got := ipv6Addresses(s); len(got) != 1 || !hasLinkLocal(got) {
		t.Errorf("IPv6 addresses at MTU 1280 = %v, want only the generated link-local address", got)
	}
	if err := s.AddProtocolAddress(mtuTestNIC, mtuTestIPv6, stack.AddressProperties{}); err != nil {
		t.Errorf("AddProtocolAddress at MTU 1280: %v", err)
	}
}

func TestNICCreatedBelow1280HasNoIPv6(t *testing.T) {
	s := newMTUTestStack(t, 1000, header.IPv4MinimumMTU)
	if err := s.EnableNIC(mtuTestNIC); err != nil {
		t.Fatalf("EnableNIC: %v", err)
	}
	if got := ipv6Addresses(s); len(got) != 0 {
		t.Errorf("IPv6 addresses of a NIC with MTU 1000 = %v, want none", got)
	}
	if err := s.SetNICMTU(mtuTestNIC, 1500); err != nil {
		t.Fatal(err)
	}
	if got := ipv6Addresses(s); !hasLinkLocal(got) {
		t.Errorf("IPv6 addresses after the MTU rises to 1500 = %v, want a link-local address", got)
	}
}

func TestNICWithoutMTUBoundsKeepsIPv6AtALowMTU(t *testing.T) {
	s := newMTUTestStack(t, 1500, 0)
	if err := s.EnableNIC(mtuTestNIC); err != nil {
		t.Fatalf("EnableNIC: %v", err)
	}
	if err := s.SetNICMTU(mtuTestNIC, 1000); err != nil {
		t.Fatal(err)
	}
	if got := ipv6Addresses(s); !hasLinkLocal(got) {
		t.Errorf("IPv6 addresses at MTU 1000 without bounds = %v, want the link-local address to stay", got)
	}
}
