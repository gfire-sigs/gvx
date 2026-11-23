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
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

func TestNATRelayCancelsPendingHandshake(t *testing.T) {
	link := channel.New(1, 1500, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() {
		s.Close()
		link.Close()
		s.Wait()
	})
	const nic = 1
	id := stack.TransportEndpointID{
		LocalAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), LocalPort: 8080,
		RemoteAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), RemotePort: 40000,
	}
	if err := s.CreateNIC(nic, link); err != nil {
		t.Fatalf("create NIC: %v", err)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: id.LocalAddress.WithPrefix()}
	if err := s.AddProtocolAddress(nic, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("add local address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nic}})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan tcpip.Error, 1)
	fwd := tcp.NewForwarder(s, 0, 1, func(r *tcp.ForwarderRequest) {
		ep, err := r.CreateNATRelayEndpoint(ctx, new(waiter.Queue))
		if ep != nil {
			ep.Abort()
		}
		r.Complete(false)
		done <- err
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	raw := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(raw)), TTL: 64, Protocol: uint8(tcp.ProtocolNumber),
		SrcAddr: id.RemoteAddress, DstAddr: id.LocalAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	syn := header.TCP(raw[header.IPv4MinimumSize:])
	syn.Encode(&header.TCPFields{
		SrcPort: id.RemotePort, DstPort: id.LocalPort, SeqNum: 1000,
		DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, id.RemoteAddress, id.LocalAddress, header.TCPMinimumSize)
	syn.SetChecksum(^syn.CalculateChecksum(xsum))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()

	bound, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	reply := link.ReadContext(bound)
	if reply == nil {
		t.Fatal("forwarder sent no SYN-ACK")
	}
	flags := header.TCP(reply.TransportHeader().Slice()).Flags()
	reply.DecRef()
	if want := header.TCPFlagSyn | header.TCPFlagAck; flags != want {
		t.Fatalf("first reply flags = %v, want %v", flags, want)
	}

	// The guest sends no ACK. Cancellation must release the endpoint.
	cancel()
	select {
	case err := <-done:
		if _, ok := err.(*tcpip.ErrAborted); !ok {
			t.Fatalf("pending handshake returned %v, want ErrAborted", err)
		}
	case <-bound.Done():
		t.Fatal("pending handshake did not return after cancellation")
	}
	if ep := s.FindTransportEndpoint(ipv4.ProtocolNumber, tcp.ProtocolNumber, id, nic); ep != nil {
		t.Fatal("the canceled endpoint remains registered")
	}
}
