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
	"bytes"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// bridgeHost is the far end of a veth pair whose near end is a bridge port. It
// records the frames that the bridge sends to the port and sends frames into
// the port.
type bridgeHost struct {
	end    *veth.Endpoint
	mac    tcpip.LinkAddress
	frames chan []byte
}

func (h *bridgeHost) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	h.frames <- pkt.Data().AsRange().ToSlice()
}

func (h *bridgeHost) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// send writes one Ethernet frame with the given addresses and a payload that
// names the frame.
func (h *bridgeHost) send(src, dst tcpip.LinkAddress, payload string) {
	frame := make([]byte, header.EthernetMinimumSize, header.EthernetMinimumSize+len(payload))
	header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: src, DstAddr: dst, Type: 0x88b5})
	frame = append(frame, payload...)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	h.end.WritePackets(list)
}

// received returns the payloads that the host got so far, in order.
func (h *bridgeHost) received() []string {
	var got []string
	for {
		select {
		case f := <-h.frames:
			got = append(got, string(f[header.EthernetMinimumSize:]))
		default:
			return got
		}
	}
}

// testBridge is a bridge with three ports and one address on the bridge.
type testBridge struct {
	t     *testing.T
	stack *stack.Stack
	mac   tcpip.LinkAddress
	hosts [3]*bridgeHost
}

const (
	bridgeNICID = 1
	sentinel    = "sentinel"
)

var (
	bridgeIP = tcpip.AddrFrom4([4]byte{10, 0, 0, 254})
	macs     = [3]tcpip.LinkAddress{
		"\x02\x00\x00\x00\x00\x01",
		"\x02\x00\x00\x00\x00\x02",
		"\x02\x00\x00\x00\x00\x03",
	}
)

func newTestBridge(t *testing.T) *testBridge {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              faketime.NewManualClock(),
	})
	b := &testBridge{t: t, stack: s}
	br := stack.NewBridgeEndpoint(1500)
	if err := s.CreateNIC(bridgeNICID, br); err != nil {
		t.Fatalf("CreateNIC(bridge): %s", err)
	}
	b.mac = br.LinkAddress()
	for i := range b.hosts {
		port, far := veth.NewPair(1500, 64)
		id := tcpip.NICID(10 + i)
		if err := s.CreateNIC(id, ethernet.New(port)); err != nil {
			t.Fatalf("CreateNIC(port %d): %s", i, err)
		}
		if err := s.SetNICCoordinator(id, bridgeNICID); err != nil {
			t.Fatalf("SetNICCoordinator(port %d): %s", i, err)
		}
		h := &bridgeHost{end: far, mac: macs[i], frames: make(chan []byte, 64)}
		far.Attach(h)
		b.hosts[i] = h
	}
	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: bridgeIP.WithPrefix(),
	}
	if err := s.AddProtocolAddress(bridgeNICID, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: bridgeNICID}})
	return b
}

// settle sends a broadcast from host 'from' behind the frame under test and
// waits until every other host got it. The veth pair of a host handles its
// frames in order, so the bridge decided about each earlier frame of the host by
// then. The sentinel itself is not part of the result. The bridge learns the
// address of the sender through the sentinel.
func (b *testBridge) settle(from int) [3][]string {
	b.t.Helper()
	b.hosts[from].send(b.hosts[from].mac, header.EthernetBroadcastAddress, sentinel)
	var out [3][]string
	for i, h := range b.hosts {
		if i == from {
			continue
		}
		deadline := time.After(5 * time.Second)
		for done := false; !done; {
			select {
			case f := <-h.frames:
				p := string(f[header.EthernetMinimumSize:])
				if p == sentinel {
					done = true
				} else {
					out[i] = append(out[i], p)
				}
			case <-deadline:
				b.t.Fatalf("host %d did not get the sentinel", i)
			}
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (b *testBridge) requireReceived(got [3][]string, want [3][]string) {
	b.t.Helper()
	for i := range got {
		if !equalStrings(got[i], want[i]) {
			b.t.Errorf("host %d received %q, want %q", i, got[i], want[i])
		}
	}
}

// learn makes the bridge learn the address of each host.
func (b *testBridge) learn() {
	b.t.Helper()
	for i := range b.hosts {
		b.settle(i)
	}
}

func TestBridgeForwarding(t *testing.T) {
	t.Run("unknown unicast goes to every other port", func(t *testing.T) {
		b := newTestBridge(t)
		b.hosts[0].send(macs[0], "\x02\x00\x00\x00\x00\x99", "to-unknown")
		b.requireReceived(b.settle(0), [3][]string{nil, {"to-unknown"}, {"to-unknown"}})
	})

	t.Run("known unicast goes to one port", func(t *testing.T) {
		b := newTestBridge(t)
		b.learn()
		b.hosts[0].send(macs[0], macs[2], "to-two")
		b.requireReceived(b.settle(0), [3][]string{nil, nil, {"to-two"}})
	})

	t.Run("unicast to the bridge stays on the bridge", func(t *testing.T) {
		b := newTestBridge(t)
		b.learn()
		b.hosts[0].send(macs[0], b.mac, "to-bridge")
		b.requireReceived(b.settle(0), [3][]string{})
	})

	t.Run("an address that moves to another port follows", func(t *testing.T) {
		b := newTestBridge(t)
		b.learn()
		// Host 1 now sends with the address of host 2.
		b.hosts[1].send(macs[2], header.EthernetBroadcastAddress, "moved")
		b.settle(1)
		b.hosts[0].send(macs[0], macs[2], "to-moved")
		got := b.settle(0)
		b.requireReceived(got, [3][]string{nil, {"to-moved"}, nil})
	})
}

func TestBridgeIPOutputFollowsFDB(t *testing.T) {
	send := func(b *testBridge, dst tcpip.Address) {
		t.Helper()
		var wq waiter.Queue
		ep, err := b.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatalf("NewEndpoint: %s", err)
		}
		defer ep.Close()
		var r bytes.Reader
		r.Reset([]byte("datagram"))
		if _, err := ep.Write(&r, tcpip.WriteOptions{To: &tcpip.FullAddress{Addr: dst, Port: 9}}); err != nil {
			t.Fatalf("Write: %s", err)
		}
	}
	neighbor := tcpip.AddrFrom4([4]byte{10, 0, 0, 3})

	// frameCounts returns how many frames each host got besides the sentinel.
	frameCounts := func(b *testBridge) [3]int {
		got := b.settle(0)
		return [3]int{len(b.hosts[0].received()), len(got[1]), len(got[2])}
	}

	t.Run("a learned neighbor gets the datagram on its port only", func(t *testing.T) {
		b := newTestBridge(t)
		if err := b.stack.AddStaticNeighbor(bridgeNICID, ipv4.ProtocolNumber, neighbor, macs[2]); err != nil {
			t.Fatalf("AddStaticNeighbor: %s", err)
		}
		b.learn()
		send(b, neighbor)
		if got, want := frameCounts(b), [3]int{0, 0, 1}; got != want {
			t.Errorf("frames per host = %v, want %v", got, want)
		}
	})

	t.Run("an unknown neighbor gets the datagram on every port", func(t *testing.T) {
		b := newTestBridge(t)
		if err := b.stack.AddStaticNeighbor(bridgeNICID, ipv4.ProtocolNumber, neighbor, "\x02\x00\x00\x00\x00\x99"); err != nil {
			t.Fatalf("AddStaticNeighbor: %s", err)
		}
		b.learn()
		send(b, neighbor)
		if got, want := frameCounts(b), [3]int{1, 1, 1}; got != want {
			t.Errorf("frames per host = %v, want %v", got, want)
		}
	})
}

func TestBridgeDeliversIPv4ToOtherPortMAC(t *testing.T) {
	b := newTestBridge(t)
	var wq waiter.Queue
	ep, tcpErr := b.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint: %s", tcpErr)
	}
	defer ep.Close()
	if err := ep.Bind(tcpip.FullAddress{Port: 9009}); err != nil {
		t.Fatalf("Bind: %s", err)
	}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	// Send an IPv4/UDP packet into port 0 addressed Ethernet-wise to port 1's MAC.
	port1MAC := b.stack.NICInfo()[tcpip.NICID(11)].LinkAddress
	payload := []byte("to-other-port-mac")
	udpLen := header.UDPMinimumSize + len(payload)
	frame := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+udpLen)
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: macs[0],
		DstAddr: port1MAC,
		Type:    header.IPv4ProtocolNumber,
	})
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + udpLen),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		DstAddr:     bridgeIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(frame[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 41000, DstPort: 9009, Length: uint16(udpLen)})
	copy(frame[len(frame)-len(payload):], payload)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	b.hosts[0].end.WritePackets(list)

	var got bytes.Buffer
	for {
		_, err := ep.Read(&got, tcpip.ReadOptions{})
		if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
			if err != nil {
				t.Fatalf("Read: %s", err)
			}
			break
		}
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for datagram addressed to sibling bridge port MAC")
		}
	}
	if got.String() != string(payload) {
		t.Fatalf("payload = %q, want %q", got.String(), string(payload))
	}
}
