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

package stack_test

import (
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

func TestListeningEndpointsAndHasBoundEndpoint(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	defer s.Close()

	const nicID = tcpip.NICID(1)
	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	loAddr := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: loAddr, PrefixLen: 8},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(v4): %s", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: header.IPv6Loopback, PrefixLen: 128},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(v6): %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	if got := s.ListeningEndpoints(); len(got) != 0 {
		t.Fatalf("ListeningEndpoints on empty stack = %+v, want empty", got)
	}

	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: nicID, Addr: loAddr, Port: 25433}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	got := s.ListeningEndpoints()
	if len(got) != 1 || got[0].LocalPort != 25433 || got[0].LocalAddr != loAddr || got[0].TransProto != header.TCPProtocolNumber {
		t.Fatalf("ListeningEndpoints after ListenTCP = %+v, want one TCP endpoint on 127.0.0.1:25433", got)
	}
	if !s.HasBoundEndpoint(header.IPv4ProtocolNumber, header.TCPProtocolNumber, loAddr, 25433) {
		t.Fatal("HasBoundEndpoint(TCP 127.0.0.1:25433) = false, want true")
	}
	if s.HasBoundEndpoint(header.IPv4ProtocolNumber, header.TCPProtocolNumber, tcpip.Address{}, 25433) {
		t.Fatal("HasBoundEndpoint(TCP wildcard:25433) = true, want false")
	}

	// Connected client/server TCP sockets must not appear in ListeningEndpoints.
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		accepted <- err
	}()
	clientConn, err := gonet.DialTCP(s, tcpip.FullAddress{NIC: nicID, Addr: loAddr, Port: 25433}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer clientConn.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := s.ListeningEndpoints(); len(got) != 1 || got[0].LocalPort != 25433 {
		t.Fatalf("ListeningEndpoints with active TCP connection = %+v, want only the listener on 25433", got)
	}

	// Dual-stack IPv6 wildcard registers under both IPv4 and IPv6.
	v6Ln, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: 25435}, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP([::]:25435): %v", err)
	}
	defer v6Ln.Close()
	if !s.HasBoundEndpoint(header.IPv4ProtocolNumber, header.TCPProtocolNumber, tcpip.Address{}, 25435) {
		t.Fatal("HasBoundEndpoint(IPv4 TCP wildcard:25435) = false for dual-stack [::]:25435, want true")
	}
	var sawV4, sawV6 bool
	for _, ep := range s.ListeningEndpoints() {
		if ep.LocalPort == 25435 && ep.LocalAddr.Len() == 0 {
			if ep.NetProto == header.IPv4ProtocolNumber {
				sawV4 = true
			}
			if ep.NetProto == header.IPv6ProtocolNumber {
				sawV6 = true
			}
		}
	}
	if !sawV4 || !sawV6 {
		t.Fatalf("ListeningEndpoints for dual-stack [::]:25435 sawV4=%v sawV6=%v, want both true", sawV4, sawV6)
	}

	udpConn, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: nicID, Addr: loAddr, Port: 25434}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer udpConn.Close()

	if !s.HasBoundEndpoint(header.IPv4ProtocolNumber, header.UDPProtocolNumber, loAddr, 25434) {
		t.Fatal("HasBoundEndpoint(UDP 127.0.0.1:25434) = false, want true")
	}

	_ = ln.Close()
	_ = v6Ln.Close()
	if got := s.ListeningEndpoints(); len(got) != 0 {
		t.Fatalf("ListeningEndpoints after Close = %+v, want empty", got)
	}
}
