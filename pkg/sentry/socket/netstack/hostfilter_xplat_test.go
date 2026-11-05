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
	"bytes"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

var (
	hostFilterNICAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	hostFilterPeer    = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	hostFilterOther   = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x99")
	hostFilterSender  = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
)

// hostFilterFrame builds an Ethernet frame that carries one UDP datagram from
// the peer to the NIC address, port 9.
func hostFilterFrame(dst tcpip.LinkAddress, payload string) []byte {
	const udpLen = header.UDPMinimumSize
	total := header.EthernetMinimumSize + header.IPv4MinimumSize + udpLen + len(payload)
	frame := make([]byte, total)
	header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: hostFilterSender, DstAddr: dst, Type: header.IPv4ProtocolNumber})
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + udpLen + len(payload)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     hostFilterPeer,
		DstAddr:     hostFilterNICAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(frame[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 5000, DstPort: 9, Length: uint16(udpLen + len(payload))})
	copy(frame[total-len(payload):], payload)
	return frame
}

func sendHostFilterFrame(far *veth.Endpoint, frame []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	far.WritePackets(list)
}

// hostFilterNIC is a veth NIC as newVeth builds it, with an address and a UDP
// endpoint on port 9.
type hostFilterNIC struct {
	far    *veth.Endpoint
	mac    tcpip.LinkAddress
	events *waiter.Queue
	udp    tcpip.Endpoint
}

func newHostFilterStack(t *testing.T) (*stack.Stack, *hostFilterNIC) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              faketime.NewManualClock(),
	})
	near, far := veth.NewPair(1500, 64)
	if err := s.CreateNIC(1, newVethNICEndpoint(near)); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: hostFilterNICAddr.WithPrefix()}
	if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	n := &hostFilterNIC{far: far, mac: s.NICInfo()[1].LinkAddress, events: &waiter.Queue{}}
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, n.events)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Addr: hostFilterNICAddr, Port: 9}); err != nil {
		t.Fatalf("Bind: %s", err)
	}
	n.udp = ep
	return s, n
}

// readDatagram returns the next datagram of the UDP endpoint.
func (n *hostFilterNIC) readDatagram(t *testing.T) string {
	t.Helper()
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	n.events.EventRegister(&we)
	defer n.events.EventUnregister(&we)
	for {
		var got bytes.Buffer
		_, err := n.udp.Read(&got, tcpip.ReadOptions{})
		if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
			if err != nil {
				t.Fatalf("Read: %s", err)
			}
			return got.String()
		}
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("no datagram arrived")
		}
	}
}

// TestHostFilterDropsFramesForOtherHosts checks that a veth NIC passes a frame
// for its own address to the IP layer and ignores a frame for another address.
func TestHostFilterDropsFramesForOtherHosts(t *testing.T) {
	_, n := newHostFilterStack(t)
	sendHostFilterFrame(n.far, hostFilterFrame(hostFilterOther, "other"))
	sendHostFilterFrame(n.far, hostFilterFrame(n.mac, "own"))
	sendHostFilterFrame(n.far, hostFilterFrame(header.EthernetBroadcastAddress, "broadcast"))

	for _, want := range []string{"own", "broadcast"} {
		if got := n.readDatagram(t); got != want {
			t.Fatalf("datagram = %q, want %q", got, want)
		}
	}
}

// frameSink records the frames that a veth end receives.
type frameSink chan []byte

func (f frameSink) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	f <- pkt.Data().AsRange().ToSlice()
}

func (frameSink) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestHostFilterKeepsBridgePortsForwarding checks that a veth NIC which became a
// bridge port still passes frames for other hosts to the bridge.
func TestHostFilterKeepsBridgePortsForwarding(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		Clock:            faketime.NewManualClock(),
	})
	if err := s.CreateNIC(1, stack.NewBridgeEndpoint(1500)); err != nil {
		t.Fatalf("CreateNIC(bridge): %s", err)
	}
	var far [2]*veth.Endpoint
	sinks := [2]frameSink{make(frameSink, 8), make(frameSink, 8)}
	for i := range far {
		near, f := veth.NewPair(1500, 64)
		id := tcpip.NICID(10 + i)
		if err := s.CreateNIC(id, newVethNICEndpoint(near)); err != nil {
			t.Fatalf("CreateNIC(port %d): %s", i, err)
		}
		if err := s.SetNICCoordinator(id, 1); err != nil {
			t.Fatalf("SetNICCoordinator(port %d): %s", i, err)
		}
		f.Attach(sinks[i])
		far[i] = f
	}

	sendHostFilterFrame(far[0], hostFilterFrame(hostFilterOther, "forwarded"))
	select {
	case <-sinks[1]:
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge did not forward a frame for another host")
	}
}
