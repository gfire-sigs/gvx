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

package ipv6_test

import (
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	nodeLoID, nodeEthID, nodeBridgeID, nodeEth1ID = 1, 2, 3, 4
	nodePort                                      = 6443
)

var (
	nodeEthAddr  = tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 2, 14: 0, 15: 15})
	nodeEthNet   = tcpip.AddressWithPrefix{Address: nodeEthAddr, PrefixLen: 64}
	nodeGateway  = tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 2, 15: 2})
	nodeBridge   = tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0xfd, 0x42, 15: 1}), PrefixLen: 64}
	nodePodAddr  = tcpip.AddrFrom16([16]byte{0xfd, 0x42, 15: 5})
	nodeEth1Net  = tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0xfd, 0, 1, 0x68, 15: 5}), PrefixLen: 64}
	internetPeer = tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x48, 0x60, 15: 0x88})
)

// node models a Kubernetes node with IPv6: eth0 has the default route, the
// bridge cni0 has the route of the pod subnet, and a TCP listener waits on the
// port of the API server.
type node struct {
	s                 *stack.Stack
	eth, bridge, eth1 *channel.Endpoint
}

func newNode(t *testing.T, withEth1 bool) *node {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	n := &node{s: s, eth: channel.New(256, 1500, ""), bridge: channel.New(256, 1500, ""), eth1: channel.New(256, 1500, "")}
	type nicSpec struct {
		id   tcpip.NICID
		ep   stack.LinkEndpoint
		addr tcpip.AddressWithPrefix
	}
	nics := []nicSpec{
		{nodeLoID, loopback.New(), tcpip.AddressWithPrefix{Address: header.IPv6Loopback, PrefixLen: 128}},
		{nodeEthID, n.eth, nodeEthNet},
		{nodeBridgeID, n.bridge, nodeBridge},
	}
	routes := []tcpip.Route{
		{Destination: tcpip.AddressWithPrefix{Address: header.IPv6Loopback, PrefixLen: 128}.Subnet(), NIC: nodeLoID},
		{Destination: nodeBridge.Subnet(), NIC: nodeBridgeID},
		{Destination: nodeEthNet.Subnet(), NIC: nodeEthID},
	}
	if withEth1 {
		nics = append(nics, nicSpec{nodeEth1ID, n.eth1, nodeEth1Net})
		routes = append(routes, tcpip.Route{Destination: nodeEth1Net.Subnet(), NIC: nodeEth1ID})
	}
	routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, Gateway: nodeGateway, NIC: nodeEthID})
	for _, nic := range nics {
		if err := s.CreateNIC(nic.id, nic.ep); err != nil {
			t.Fatalf("CreateNIC(%d): %v", nic.id, err)
		}
		pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: nic.addr}
		if err := s.AddProtocolAddress(nic.id, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", nic.id, err)
		}
	}
	s.SetRouteTable(routes)
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwardingDefaultAndAllNICs: %v", err)
	}

	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	t.Cleanup(ep.Close)
	if err := ep.Bind(tcpip.FullAddress{Port: nodePort}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := ep.Listen(256); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return n
}

// holdLoopbackCopy makes the loopback NIC own a temporary copy of the address
// of eth0, as a local route of the node does while a connection uses it.
func (n *node) holdLoopbackCopy(t *testing.T) {
	t.Helper()
	r, err := n.s.FindRoute(0, nodeEthAddr, nodeEthAddr, ipv6.ProtocolNumber, false)
	if err != nil {
		t.Fatalf("FindRoute(local): %v", err)
	}
	t.Cleanup(r.Release)
	if got := n.s.CheckLocalAddress(nodeLoID, ipv6.ProtocolNumber, nodeEthAddr); got != nodeLoID {
		t.Fatalf("CheckLocalAddress(lo, %s) = %d, want %d: the loopback NIC has no copy", nodeEthAddr, got, nodeLoID)
	}
}

func readWithin(ep *channel.Endpoint, d time.Duration) *stack.PacketBuffer {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return ep.ReadContext(ctx)
}

// TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer is the IPv6 form of the
// IPv4 test of the same name. A pod connects to the address of eth0 through the
// bridge, and the SYN-ACK must leave through the bridge, not the default route.
func TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		loopback bool
	}{
		{"eth0 owns the address", false},
		{"eth0 and the loopback copy own the address", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNode(t, false)
			if tc.loopback {
				n.holdLoopbackCopy(t)
			}
			const syns = 64
			for i := 0; i < syns; i++ {
				n.bridge.InjectInbound(ipv6.ProtocolNumber, synPacket(nodePodAddr, nodeEthAddr, uint16(40000+i), nodePort))
			}
			for i := 0; i < syns; i++ {
				pkt := readWithin(n.bridge, 5*time.Second)
				if pkt == nil {
					t.Fatalf("SYN-ACK %d did not leave through the bridge; eth0 sent %d packets", i, n.eth.Drain())
				}
				pkt.DecRef()
			}
			if got := n.eth.Drain(); got != 0 {
				t.Errorf("eth0 sent %d packets for the pod, want 0", got)
			}
		})
	}
}

// TestSynOnSecondNICAnswersThroughTheRouteTable checks a host with two NICs. A
// SYN from the Internet arrives on eth1 for the address of eth0, and the reply
// leaves through the default route of eth0, as in Linux.
func TestSynOnSecondNICAnswersThroughTheRouteTable(t *testing.T) {
	n := newNode(t, true)
	n.eth1.InjectInbound(ipv6.ProtocolNumber, synPacket(internetPeer, nodeEthAddr, 40000, nodePort))
	pkt := readWithin(n.eth, 5*time.Second)
	if pkt == nil {
		t.Fatalf("the SYN-ACK did not leave through eth0; eth1 sent %d packets", n.eth1.Drain())
	}
	pkt.DecRef()
	if got := n.eth1.Drain(); got != 0 {
		t.Errorf("eth1 sent %d packets, want 0", got)
	}
}

// synPacket returns an IPv6 packet with a TCP SYN from src to dst.
func synPacket(src, dst tcpip.Address, srcPort, dstPort uint16) *stack.PacketBuffer {
	b := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	ip := header.IPv6(b)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: tcp.ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	th := header.TCP(b[header.IPv6MinimumSize:])
	th.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, header.TCPMinimumSize)
	th.SetChecksum(^th.CalculateChecksum(xsum))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
}
