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
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	nodeLoID, nodeEthID, nodeBridgeID, nodeEth1ID = 1, 2, 3, 4
	nodePort                                      = 6443
)

var (
	nodeEthAddr  = tcpip.AddrFrom4([4]byte{10, 0, 2, 15})
	nodeEth1Addr = tcpip.AddrFrom4([4]byte{192, 168, 1, 5})
	nodePodAddr  = tcpip.AddrFrom4([4]byte{10, 42, 0, 5})
)

// node is a stack that models a Kubernetes node. eth0 has the default route,
// the bridge cni0 has the route of the pod subnet, and a TCP listener waits on
// the port of the API server. The stack has HandleLocal, as the stack of a
// sandbox has.
type node struct {
	s                 *stack.Stack
	eth, bridge, eth1 *channel.Endpoint
}

// newNode creates the stack. With eth1 it adds a second NIC without a default
// route. With forwarding off, the stack does not forward between its NICs.
func newNode(t *testing.T, forwarding, withEth1 bool) *node {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	n := &node{s: s, eth: channel.New(256, 1500, ""), bridge: channel.New(256, 1500, ""), eth1: channel.New(256, 1500, "")}
	nics := []struct {
		id   tcpip.NICID
		ep   stack.LinkEndpoint
		addr tcpip.AddressWithPrefix
	}{
		{nodeLoID, loopback.New(), tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), PrefixLen: 8}},
		{nodeEthID, n.eth, tcpip.AddressWithPrefix{Address: nodeEthAddr, PrefixLen: 24}},
		{nodeBridgeID, n.bridge, tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 42, 0, 1}), PrefixLen: 24}},
	}
	routes := []tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: nodeLoID},
		{Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 42, 0, 0}), PrefixLen: 24}.Subnet(), NIC: nodeBridgeID},
		{Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 2, 0}), PrefixLen: 24}.Subnet(), NIC: nodeEthID},
	}
	if withEth1 {
		nics = append(nics, struct {
			id   tcpip.NICID
			ep   stack.LinkEndpoint
			addr tcpip.AddressWithPrefix
		}{nodeEth1ID, n.eth1, tcpip.AddressWithPrefix{Address: nodeEth1Addr, PrefixLen: 24}})
		routes = append(routes, tcpip.Route{Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 168, 1, 0}), PrefixLen: 24}.Subnet(), NIC: nodeEth1ID})
	}
	routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), NIC: nodeEthID})
	for _, nic := range nics {
		if err := s.CreateNIC(nic.id, nic.ep); err != nil {
			t.Fatalf("CreateNIC(%d): %v", nic.id, err)
		}
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: nic.addr}
		if err := s.AddProtocolAddress(nic.id, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", nic.id, err)
		}
	}
	s.SetRouteTable(routes)
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, forwarding); err != nil {
		t.Fatalf("SetForwardingDefaultAndAllNICs: %v", err)
	}

	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
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
// of eth0, as a local route of the node does while a connection uses it. The
// test keeps the copy until it ends.
func (n *node) holdLoopbackCopy(t *testing.T) {
	t.Helper()
	r, err := n.s.FindRoute(0, nodeEthAddr, nodeEthAddr, ipv4.ProtocolNumber, false)
	if err != nil {
		t.Fatalf("FindRoute(local): %v", err)
	}
	t.Cleanup(r.Release)
	if got := n.s.CheckLocalAddress(nodeLoID, ipv4.ProtocolNumber, nodeEthAddr); got != nodeLoID {
		t.Fatalf("CheckLocalAddress(lo, %s) = %d, want %d: the loopback NIC has no copy", nodeEthAddr, got, nodeLoID)
	}
}

// readWithin returns the next packet that ep sent, or nil after d.
func readWithin(ep *channel.Endpoint, d time.Duration) *stack.PacketBuffer {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return ep.ReadContext(ctx)
}

// TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer checks the model of a
// Kubernetes node. A pod connects to the address of eth0, and the packet arrives
// on the bridge. The default route leaves through eth0, and the route of the pod
// subnet leaves through the bridge. Linux sends the SYN-ACK through the bridge,
// because the route table of the destination decides, and not the NIC that owns
// the source address of the reply. The loopback copy of the address was the
// cause of the random choice between eth0 and lo.
func TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		loopback bool
	}{
		{"eth0 owns the address", false},
		{"eth0 and the loopback copy own the address", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNode(t, true, false)
			if tc.loopback {
				n.holdLoopbackCopy(t)
			}
			// Each SYN uses its own source port, as each probe of a pod does.
			const syns = 64
			for i := 0; i < syns; i++ {
				n.bridge.InjectInbound(ipv4.ProtocolNumber, synPacket(nodePodAddr, nodeEthAddr, uint16(40000+i), nodePort))
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

// TestForwardedBroadcastIsNotAnswered checks that a packet for the directed
// broadcast address of eth0 still counts as a broadcast when it arrives on the
// bridge. A TCP listener must not answer a SYN to a broadcast address.
func TestForwardedBroadcastIsNotAnswered(t *testing.T) {
	n := newNode(t, true, false)
	n.holdLoopbackCopy(t)
	broadcast := tcpip.AddrFrom4([4]byte{10, 0, 2, 255})
	for i := 0; i < 8; i++ {
		n.bridge.InjectInbound(ipv4.ProtocolNumber, synPacket(nodePodAddr, broadcast, uint16(40000+i), nodePort))
	}
	if pkt := readWithin(n.bridge, 500*time.Millisecond); pkt != nil {
		t.Fatalf("the stack answered a SYN to the broadcast address through the bridge")
	}
	if got := n.eth.Drain(); got != 0 {
		t.Errorf("eth0 sent %d packets for a SYN to the broadcast address, want 0", got)
	}
}

// TestSynOnSecondNICAnswersThroughTheRouteTable checks a host with two NICs. A
// SYN from the Internet arrives on eth1 for the address of eth0. eth1 has no
// route to the sender, so the reply leaves through the default route of eth0, as
// in Linux.
func TestSynOnSecondNICAnswersThroughTheRouteTable(t *testing.T) {
	n := newNode(t, true, true)
	sender := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	n.eth1.InjectInbound(ipv4.ProtocolNumber, synPacket(sender, nodeEthAddr, 40000, nodePort))
	pkt := readWithin(n.eth, 5*time.Second)
	if pkt == nil {
		t.Fatalf("the SYN-ACK did not leave through eth0; eth1 sent %d packets", n.eth1.Drain())
	}
	pkt.DecRef()
	if got := n.eth1.Drain(); got != 0 {
		t.Errorf("eth1 sent %d packets, want 0", got)
	}
}

// TestForwardedSynIsNotAnsweredWithoutForwarding checks that the change keeps
// the old limit of the stack: without forwarding, a packet for an address of
// another NIC is not delivered.
func TestForwardedSynIsNotAnsweredWithoutForwarding(t *testing.T) {
	n := newNode(t, false, false)
	n.bridge.InjectInbound(ipv4.ProtocolNumber, synPacket(nodePodAddr, nodeEthAddr, 40000, nodePort))
	if pkt := readWithin(n.bridge, 500*time.Millisecond); pkt != nil {
		t.Fatalf("the stack answered through the bridge without forwarding")
	}
	if got := n.eth.Drain(); got != 0 {
		t.Errorf("eth0 sent %d packets without forwarding, want 0", got)
	}
}

// synPacket returns an IPv4 packet with a TCP SYN from src to dst.
func synPacket(src, dst tcpip.Address, srcPort, dstPort uint16) *stack.PacketBuffer {
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	th := header.TCP(b[header.IPv4MinimumSize:])
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
