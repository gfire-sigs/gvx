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

package netbackend

import (
	"fmt"
	"math/rand"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/nftables"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/raw"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

// LoopbackNICName and Eth0NICName are the interface names that the guest sees
// for LoopbackNICID and Eth0NICID.
const (
	LoopbackNICName = "lo"
	Eth0NICName     = "eth0"
)

// defaultTTL is the default IP time to live of Linux.
const defaultTTL = 64

// StackOptions selects the optional features of a guest network stack. The
// zero value gives the default stack of a gvx guest.
type StackOptions struct {
	// RawSockets lets the guest open raw IP sockets. A raw socket can send
	// packets with any source address on the guest network. The NAT forwarder
	// still applies its destination rules to every packet that leaves eth0.
	RawSockets bool

	// IPTables creates the initial iptables tables when RawSockets is set,
	// such as netfilter.DefaultLinuxTables of the Sentry. When nil, the stack
	// uses its built-in empty tables.
	IPTables func(clock tcpip.Clock, rand *rand.Rand) *stack.IPTables

	// PacketSocketWrite lets the guest send packets on AF_PACKET sockets.
	PacketSocketWrite bool
}

// newStack creates an empty guest network stack with the protocols and the
// options that runsc gives its sandbox stack.
func newStack(opts StackOptions) (*stack.Stack, error) {
	sopts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal:              true,
		AllowPacketEndpointWrite: opts.PacketSocketWrite,
	}
	if opts.RawSockets {
		sopts.RawFactory = raw.EndpointFactory{}
		sopts.DefaultIPTables = opts.IPTables
	}
	s := stack.New(sopts)
	if opts.RawSockets && nftables.IsNFTablesEnabled() {
		s.SetNFTables(nftables.NewNFTables(s, s.Clock(), s.SecureRNG()))
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		s.Close()
		return nil, fmt.Errorf("netbackend: enable TCP SACK: %s", err)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		s.Close()
		return nil, fmt.Errorf("netbackend: enable TCP receive buffer tuning: %s", err)
	}
	ttl := tcpip.DefaultTTLOption(defaultTTL)
	for _, proto := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		if err := s.SetNetworkProtocolOption(proto, &ttl); err != nil {
			s.Close()
			return nil, fmt.Errorf("netbackend: set the default TTL of protocol %d: %s", proto, err)
		}
	}
	return s, nil
}

// createNamedNIC creates a NIC with the interface name that the guest sees.
func createNamedNIC(s *stack.Stack, id tcpip.NICID, name string, ep stack.LinkEndpoint) error {
	if err := s.CreateNICWithOptions(id, ep, stack.NICOptions{Name: name}); err != nil {
		return fmt.Errorf("netbackend: create %s NIC: %s", name, err)
	}
	return nil
}
