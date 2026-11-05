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

// TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer checks the model of a
// Kubernetes node. A pod connects to the address of eth0, and the packet arrives
// on the bridge. The default route leaves through eth0, and the route of the pod
// subnet leaves through the bridge. Linux sends the SYN-ACK through the bridge,
// because the route table of the destination decides, and not the NIC that owns
// the source address of the reply.
func TestForwardedSynAnswerLeavesThroughTheRouteOfThePeer(t *testing.T) {
	const (
		loID, ethID, bridgeID = 1, 2, 3
		port                  = 6443
	)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := s.CreateNIC(loID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(lo): %v", err)
	}
	eth := channel.New(64, 1500, "")
	bridge := channel.New(64, 1500, "")
	if err := s.CreateNIC(ethID, eth); err != nil {
		t.Fatalf("CreateNIC(eth0): %v", err)
	}
	if err := s.CreateNIC(bridgeID, bridge); err != nil {
		t.Fatalf("CreateNIC(cni0): %v", err)
	}
	ethAddr := tcpip.AddrFrom4([4]byte{10, 0, 2, 15})
	podAddr := tcpip.AddrFrom4([4]byte{10, 42, 0, 5})
	for id, a := range map[tcpip.NICID]tcpip.ProtocolAddress{
		loID:     {Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), PrefixLen: 8}},
		ethID:    {Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: ethAddr, PrefixLen: 24}},
		bridgeID: {Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 42, 0, 1}), PrefixLen: 24}},
	} {
		if err := s.AddProtocolAddress(id, a, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", id, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: loID},
		{Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 42, 0, 0}), PrefixLen: 24}.Subnet(), NIC: bridgeID},
		{Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 0, 2, 0}), PrefixLen: 24}.Subnet(), NIC: ethID},
		{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), NIC: ethID},
	})
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwardingDefaultAndAllNICs: %v", err)
	}

	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	defer ep.Close()
	if err := ep.Bind(tcpip.FullAddress{Port: port}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := ep.Listen(16); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Each SYN uses its own source port, as each probe of a pod does.
	for i := 0; i < 32; i++ {
		bridge.InjectInbound(ipv4.ProtocolNumber, synPacket(podAddr, ethAddr, uint16(40000+i), port))
	}
	for i := 0; i < 32; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pkt := bridge.ReadContext(ctx)
		cancel()
		if pkt == nil {
			t.Fatalf("SYN-ACK %d did not leave through the bridge; eth0 sent %d packets", i, eth.Drain())
		}
		pkt.DecRef()
	}
	if n := eth.Drain(); n != 0 {
		t.Errorf("eth0 sent %d packets for the pod, want 0", n)
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
