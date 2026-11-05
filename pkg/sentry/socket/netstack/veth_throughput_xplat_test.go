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

package netstack

import (
	"io"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/packetsocket"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
)

// vethTCPPair returns two stacks that a veth pair joins, and a listener on the
// second one. wrap builds the link endpoint of each NIC from one end of the
// pair.
func vethTCPPair(tb testing.TB, wrap func(*veth.Endpoint) stack.LinkEndpoint) (*stack.Stack, *gonet.TCPListener) {
	tb.Helper()
	var stacks [2]*stack.Stack
	a, b := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	for i, end := range []*veth.Endpoint{a, b} {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
		tb.Cleanup(func() { s.Close() })
		if err := s.CreateNIC(1, wrap(end)); err != nil {
			tb.Fatalf("CreateNIC: %v", err)
		}
		addr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 1, 0, byte(i + 1)}).WithPrefix(),
		}
		if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
			tb.Fatalf("AddProtocolAddress: %v", err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
		stacks[i] = s
	}
	ln, err := gonet.ListenTCP(stacks[1], tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 1, 0, 2}), Port: 9000}, ipv4.ProtocolNumber)
	if err != nil {
		tb.Fatalf("ListenTCP: %v", err)
	}
	tb.Cleanup(func() { ln.Close() })
	return stacks[0], ln
}

// benchmarkVethTCP sends b.N MiB through TCP over a veth pair.
func benchmarkVethTCP(b *testing.B, wrap func(*veth.Endpoint) stack.LinkEndpoint) {
	client, ln := vethTCPPair(b, wrap)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	conn, err := gonet.DialTCP(client, tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 1, 0, 2}), Port: 9000}, ipv4.ProtocolNumber)
	if err != nil {
		b.Fatalf("DialTCP: %v", err)
	}
	chunk := make([]byte, 1<<20)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for range b.N {
		if _, err := conn.Write(chunk); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
	conn.Close()
}

// BenchmarkVethTCP compares TCP throughput over a veth pair for the link that
// a veth NIC uses and for the plain Ethernet wrapper that the veth NIC used
// before the link MTU change. A link that hides the GSO methods of the veth
// endpoint makes TCP send small segments and runs slower.
func BenchmarkVethTCP(b *testing.B) {
	b.Run("plain-ethernet", func(b *testing.B) {
		benchmarkVethTCP(b, func(end *veth.Endpoint) stack.LinkEndpoint {
			return newHostFilterEndpoint(packetsocket.New(ethernet.New(end)))
		})
	})
	b.Run("veth-nic", func(b *testing.B) {
		benchmarkVethTCP(b, newVethNICEndpoint)
	})
}
